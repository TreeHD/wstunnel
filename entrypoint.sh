#!/bin/sh

# 啟動 udpgw-server (tun2proxy 版本)
# 使用 -l 0.0.0.0:7300 並開啟背景執行模式
echo "Starting udpgw-server on 0.0.0.0:7300..."
udpgw -l 0.0.0.0:7300 --daemonize

# 稍微等待確保背景行程啟動
sleep 1

# 啟動 Go 主程式並接管信號
echo "Starting wstunnel-go..."
exec ./wstunnel-go
