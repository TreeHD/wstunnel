#!/bin/sh

# ======================================================
#  Slipstream + SOCKS 模式啟動腳本
# ======================================================

set -e

DATA_DIR="/data/dnstt"
mkdir -p "$DATA_DIR"

# 1. 檢查必要變數
if [ -z "$DNSTT_DOMAIN" ]; then
    echo "[slipstream] 錯誤: 環境變數 DNSTT_DOMAIN 未設定，請在 docker-compose.yml 中填入您的 DNS 隧道域名。"
    exit 1
fi

# 2. 自動產生憑證與金鑰 (如果不存在)
# Slipstream 使用 TLS 憑證進行加密
if [ ! -f "$DATA_DIR/cert.pem" ]; then
    echo "[slipstream] 首次啟動，產生自我簽署憑證與重置種子..."
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$DATA_DIR/key.pem" \
        -out "$DATA_DIR/cert.pem" \
        -days 3650 -nodes \
        -subj "/CN=$DNSTT_DOMAIN"
    
    # 產生 32 bytes 的隨機種子
    dd if=/dev/urandom bs=32 count=1 of="$DATA_DIR/reset-seed" 2>/dev/null
    echo "[slipstream] 憑證與種子產生完成。"
fi

# 3. 配置 Dante SOCKS 代理
# 我們將 SOCKS 伺服器架設在 127.0.0.1:1080，僅供 Slipstream 內部轉發
EXT_IP=$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
if [ -z "$EXT_IP" ]; then
    # 如果無法透過 ip 指令獲取，嘗試外部 API
    EXT_IP=$(curl -s --max-time 5 ifconfig.me || echo "0.0.0.0")
fi

echo "[dante] 偵測到外部 IP: $EXT_IP，配置 SOCKS5 代理在 127.0.0.1:1080..."
cat > /etc/danted.conf <<EOF
logoutput: stderr

internal: 127.0.0.1 port = 1080
external: $EXT_IP

socksmethod: none
clientmethod: none

client pass {
    from: 127.0.0.1/32 to: 0.0.0.0/0
}

socks pass {
    from: 127.0.0.1/32 to: 0.0.0.0/0
    protocol: tcp udp
}
EOF

# 4. 啟動 Dante (背景執行)
danted -D
echo "[dante] Dante SOCKS 代理已啟動。"

# 5. 啟動 Slipstream Server (轉發至本地 1080)
echo "[slipstream] 啟動伺服器: $DNSTT_DOMAIN -> SOCKS:1080"
exec slipstream-server \
    --dns-listen-port 5300 \
    --target-address 127.0.0.1:1080 \
    --domain "$DNSTT_DOMAIN" \
    --cert "$DATA_DIR/cert.pem" \
    --key "$DATA_DIR/key.pem" \
    --reset-seed "$DATA_DIR/reset-seed"
