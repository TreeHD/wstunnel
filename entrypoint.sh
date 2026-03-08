#!/bin/sh
# 啟動 badvpn-udpgw 放背景
echo "啟動 badvpn-udpgw (127.0.0.1:7300)..."
badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 128 >/dev/null 2>&1 &

# 啟動主程式
exec ./wstunnel-go
