#!/bin/sh

# ======================================================
#  WSTunnel 容器啟動腳本
#  負責啟動所有 sidecar 服務與主程式
# ======================================================

# --- 1. UDPGW (tun2proxy) ---
echo "[entrypoint] 啟動 udpgw-server on 0.0.0.0:7300..."
udpgw -l 0.0.0.0:7300 --daemonize
sleep 1

# --- 2. 主程式 (wstunnel-go) ---
echo "[entrypoint] 啟動 wstunnel-go..."
exec ./wstunnel-go
