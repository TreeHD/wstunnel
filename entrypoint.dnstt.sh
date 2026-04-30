#!/bin/sh

# ======================================================
#  DNSTT 容器啟動腳本
# ======================================================

set -e

DATA_DIR="/data/dnstt"
mkdir -p "$DATA_DIR"

if [ -z "$DNSTT_DOMAIN" ]; then
    echo "[dnstt] 錯誤: 環境變數 DNSTT_DOMAIN 未設定，請在 docker-compose.yml 中填入您的 DNS 隧道域名。"
    exit 1
fi

UPSTREAM="${DNSTT_UPSTREAM}"
if [ -z "$UPSTREAM" ]; then
    echo "[dnstt] 錯誤: 環境變數 DNSTT_UPSTREAM 未設定。"
    echo "[dnstt] 請在 docker-compose.yml 中設定 DNSTT_UPSTREAM (例如: wstunnel:80)"
    exit 1
fi

# 首次啟動自動產生金鑰對
if [ ! -f "$DATA_DIR/server.key" ]; then
    echo "[dnstt] 首次啟動，產生 DNSTT 金鑰對..."
    dnstt-server -gen-key \
        -privkey-file "$DATA_DIR/server.key" \
        -pubkey-file "$DATA_DIR/server.pub"
    echo "=================================================="
    echo "  [重要] DNSTT 公鑰 (請提供給客戶端):"
    cat "$DATA_DIR/server.pub"
    echo "=================================================="
fi

echo "[dnstt] 啟動 dnstt-server (UDP :5300 → ${UPSTREAM})..."
echo "[dnstt] 域名: ${DNSTT_DOMAIN}"
exec dnstt-server \
    -udp :5300 \
    -privkey-file "$DATA_DIR/server.key" \
    "$DNSTT_DOMAIN" \
    "$UPSTREAM"
