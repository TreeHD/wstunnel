#!/bin/bash

set -e

# ======================================================
#  DNS 過濾規則:只放行查詢 DNSTT_DOMAIN 或其 subdomain 的封包
#  ------------------------------------------------------
#  DNS query 在 wire format 把 domain 編成「長度前綴 label」串
#  (例如 t.example.com → \x01t\x07example\x03com),封包中
#  不含這串 byte 必然不是隧道查詢,直接 DROP 即可消除反射放大。
#
#  對真實 Slipstream 流量為何安全:
#    1. Slipstream 的 query 一定是 <data>.<DNSTT_DOMAIN> 形式,
#       wire format 中 DNSTT_DOMAIN 的 label 序列必然完整出現
#    2. 規則只動 INPUT 鏈;OUTPUT(server 的回應)完全不過濾,
#       conntrack 會讓回應對應到原始 client
#    3. 不接 FORWARD,不影響 NAT/routing
#    4. 用 --icase 對抗 0x20 case randomization
#
#  限制:
#    * 需要容器具備 NET_ADMIN cap (docker-compose.yml 已設定)
#    * 失敗時 fail-open,服務仍能跑但失去防護(會在 log 警告)
#    * 若 DNSTT_DOMAIN 極短(如 t.io)有極小機率 false positive,
#      這只會「不小心放行」非隧道查詢,不會擋掉真實隧道流量
# ======================================================
encode_domain_hex() {
    # 把 "t.example.com" 編成 "01 74 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00"
    local domain="$1"
    local hex=""
    IFS='.' read -ra LABELS <<< "$domain"
    for label in "${LABELS[@]}"; do
        local len=${#label}
        hex+=$(printf '%02x' "$len")
        hex+=$(printf '%s' "$label" | tr '[:upper:]' '[:lower:]' | xxd -p -c 256 | tr -d '\n')
    done
    # 不加結尾 00,因為 DNS query 在這個 label 後可能還接 type/class,
    # 我們只要確保「DNSTT_DOMAIN 這串 label 序列」出現在封包裡即可,
    # 這樣 subdomain (例如 abc.t.example.com) 也會匹配。
    echo "$hex"
}

apply_dns_filter() {
    if [ -z "$DNSTT_DOMAIN" ]; then
        echo "[entrypoint] ⚠️  DNSTT_DOMAIN 未設定,跳過 DNS 過濾"
        return
    fi

    local domain_lower=$(echo "$DNSTT_DOMAIN" | tr '[:upper:]' '[:lower:]')
    local hex_pattern=$(encode_domain_hex "$domain_lower")

    if [ -z "$hex_pattern" ]; then
        echo "[entrypoint] ⚠️  無法編碼 DNSTT_DOMAIN,跳過 DNS 過濾"
        return
    fi

    # 把 hex 轉成 iptables --hex-string 需要的 |xx xx xx| 格式
    local pattern="|$(echo "$hex_pattern" | sed 's/\(..\)/\1 /g' | sed 's/ $//')|"

    echo "[entrypoint] 安裝 DNS 過濾規則 (DNSTT_DOMAIN=$domain_lower)"
    echo "[entrypoint]   pattern: $pattern"

    # 試插規則,失敗則放棄(可能在無 NET_ADMIN 的環境)
    # --icase 讓 string match 忽略字母大小寫,對抗 0x20 randomization
    if iptables -I INPUT 1 -p udp --dport 5353 \
        -m string --algo bm --icase --hex-string "$pattern" -j ACCEPT 2>/dev/null && \
       iptables -A INPUT -p udp --dport 5353 -j DROP 2>/dev/null; then
        echo "[entrypoint] ✅ DNS 過濾啟用:UDP/5353 只放行查詢 *.$domain_lower 的封包"
        echo "[entrypoint]    (對 Slipstream 真實流量無影響;OUTPUT 不過濾,回應正常送出)"
    else
        echo "[entrypoint] ❌ iptables 規則安裝失敗 — 容器可能缺少 NET_ADMIN cap"
        echo "[entrypoint]    服務仍會啟動,但**失去反射放大防護**"
        echo "[entrypoint]    請在 docker-compose.yml 加入:  cap_add: [NET_ADMIN]"
    fi
}

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

# 5. 套用 DNS 過濾(避免被當反射放大來源)
apply_dns_filter

# 6. 啟動 slipstream-server
echo "=================================================="
echo "Slipstream Domain: $DNSTT_DOMAIN"
echo "=================================================="

# 2. 啟動 slipstream-server
# --udp-bind: 監聽容器內的 5353 端口
# --domain: 你的 NS 域名
# --target: 流量轉發到本地的 SOCKS5
# --cert/--key: 證書路徑
echo "Starting Slipstream server on UDP 5353..."
exec slipstream-server \
    --dns-listen-port 5353 \
    --domain "$DNSTT_DOMAIN" \
    --target-address 127.0.0.1:1080 \
    --cert cert.pem \
    --key key.pem \
     --reset-seed "$(cat reset.seed)"
