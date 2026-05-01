#!/bin/bash

set -e

# 1. 檢查並生成 wgcf 配置 (Cloudflare WARP)
# 這裡使用 wgcf 直接註冊並生成配置文件
if [ ! -f "wgcf-account.toml" ]; then
    echo "Registering Cloudflare WARP account..."
    wgcf register --accept-tos
    wgcf generate
fi

# 2. 生成 wireproxy 配置 (帶有帳密驗證)
# 自動從 wgcf 生成的配置文件中提取密鑰
if [ ! -f "wireproxy.conf" ]; then
    echo "Configuring wireproxy with SOCKS5 Auth..."
    PRIVATE_KEY=$(grep PrivateKey wgcf-profile.conf | awk '{print $3}')
    PUBLIC_KEY=$(grep PublicKey wgcf-profile.conf | awk '{print $3}')
    ENDPOINT=$(grep Endpoint wgcf-profile.conf | awk '{print $3}')
    
    cat <<EOF > wireproxy.conf

WGConfig = ./wgcf-profile.conf

[Socks5]
BindAddress = 127.0.0.1:1080
EOF
fi

# 3. 生成 DNS 隧道證書與種子
if [ ! -f "cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 3650 -subj "/CN=$DOMAIN"
fi
if [ ! -f "reset.seed" ]; then
    openssl rand -hex 32 > reset.seed
fi

# 4. 啟動 wireproxy (後台運行)
wireproxy -c wireproxy.conf &

# 5. 啟動 slipstream-server
echo "=================================================="
echo "WARP SOCKS5 Auth User: ${PROXY_USER:-admin}"
echo "WARP SOCKS5 Auth Pass: ${PROXY_PASS:-password123}"
echo "Slipstream Domain: $DOMAIN"
echo "=================================================="

# 2. 啟動 slipstream-server
# --udp-bind: 監聽容器內的 5353 端口
# --domain: 你的 NS 域名
# --target: 流量轉發到本地的 SOCKS5
# --cert/--key: 證書路徑
echo "Starting Slipstream server on UDP 5353..."
exec slipstream-server \
    --dns-listen-port 5353 \
    --domain "$DOMAIN" \
    --target-address 127.0.0.1:1080 \
    --cert cert.pem \
    --key key.pem \
     --reset-seed "$(cat reset.seed)"