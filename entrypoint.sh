#!/bin/sh

# ======================================================
#  WSTunnel 容器啟動腳本
#  負責啟動所有 sidecar 服務與主程式
# ======================================================

# --- 1. UDPGW (tun2proxy) ---
# 故意只綁 127.0.0.1,避免被當成匿名 UDP 出口代理。
# wstunnel 主程式會接管 SSH direct-tcpip 對 127.0.0.1:7300 的連線,
# 進入 udpgw.go 攔截 DNS 並把其餘 UDP 轉發給此進程。
echo "[entrypoint] 啟動 udpgw-server on 127.0.0.1:7300..."
udpgw -l 127.0.0.1:7300 --daemonize
sleep 1

# --- 2. 主程式 (wstunnel-go) ---
echo "[entrypoint] 啟動 wstunnel-go..."
exec ./wstunnel-go
