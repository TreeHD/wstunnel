# wstunnel-go

> 高效能、多協定、可自部署的 SSH-over-Tunnel 代理伺服器,專為行動裝置與受限網路環境最佳化。

[![Build Status](https://github.com/TreeHD/wstunnel/actions/workflows/wstunnel-publish.yml/badge.svg)](https://github.com/TreeHD/wstunnel/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8.svg)](https://go.dev)

---

## 目錄

- [專案簡介](#專案簡介)
- [核心特性](#核心特性)
- [系統架構](#系統架構)
- [快速部署](#快速部署)
- [連線模式](#連線模式)
- [DNS 與 UDPGW](#dns-與-udpgw)
- [設定參考](#設定參考)
- [管理後台](#管理後台)
- [故障排查](#故障排查)
- [自行編譯](#自行編譯)
- [限制與已知問題](#限制與已知問題)
- [授權](#授權)

---

## 專案簡介

`wstunnel-go` 是一個基於 SSH-in-TLS 的 tunnel 代理服務,專門解決下列場景:

- **行動裝置免流連線**:整合多種偽裝協定(HTTP Upgrade、TLS+Payload、WebSocket)
  繞過運營商的計費識別,搭配 NPV Tunnel、HTTP Custom、HTTP Injector 等客戶端
- **受限網路出口**:443 埠口透過 SNI 與 User-Agent 偽裝成正常 HTTPS,難以被 DPI 識別
- **多協定統一接入**:單一二進位提供 SSH Tunnel、UDPGW、IP-over-SSH
- **不依賴外部組件解析 DNS**:伺服器內建 UDPGW 攔截器,即使機房 UDP/53 被擋仍能正常解析

整體目標是讓部署者只需 `docker compose up`,客戶端只需填 IP 與帳密,即可在
非常規的網路環境(校園網、跨境鏈路、行動數據)中取得穩定的代理連線。

---

## 核心特性

### 連線層
- **多入口偽裝**:80 (HTTP Upgrade)、443 (TLS Multiplexer)
- **SNI 白名單**:443 入口可限制只接受特定 SNI 的連線,過濾掃描器
- **User-Agent 校驗**:HTTP Upgrade 階段比對自訂 UA,不相符回 200 OK 維持假象
- **Payload 容錯**:`tolerantCopy` 對行動網路抖動具備指數退避重試,4G/Wi-Fi 切換不中斷

### DNS 子系統
- **多 DNS 伺服器 failover**:設定值支援 `8.8.8.8, 1.1.1.1:53` 逗號分隔
- **UDP 失敗自動退回 TCP**:規避機房擋 UDP/53 的常見封鎖
- **啟動健檢**:對 `cloudflare.com` 做測試查詢,結果寫入 log
- **錯誤分類**:NXDOMAIN / SERVFAIL / TIMEOUT / REFUSED 各自帶人類可讀提示
- **UDPGW DNS 攔截**:直接在 SSH channel 層接管 DNS 查詢,不經外部 udpgw 進程

### 帳號與計費
- 帳號層級可設定:啟用狀態、到期日、流量上限 (GB)、最大連線數
- 流量統計每 5 分鐘自動存盤,優雅關閉時也會強制存檔
- SSH/UDPGW 流量統一計入,可即時於後台查看

### 部署與維運
- 多階段 Docker build,跨 amd64 / arm64
- GitHub Actions 拆分 wstunnel 與 dnstt 兩條 pipeline,變更哪邊只 build 哪邊
- arm64 使用原生 runner (`ubuntu-24.04-arm`),消除 QEMU 模擬
- 中央化 log 收集器,後台可即時查看最近 200 行
- `WSTUNNEL_DEBUG=1` 環境變數開啟詳細 log,平時自動降噪

---

## 系統架構

### 流量分流圖

```
                    手機/客戶端 (NPV Tunnel / HTTP Injector)
                              │
            ┌─────────────────┴─────────────────┐
            │                                   │
        Port 80                             Port 443
     (HTTP Upgrade)                     (TLS Multiplexer)
            │                                   │
            ▼                                   ▼
     ┌──────────────────────────────────────────────────┐
     │              wstunnel-go (Go Binary)             │
     │                                                  │
     │  ┌─────────────────────────────────────────────┐ │
     │  │ dispatcher.go  ─ Peek 協定 / 偽裝握手        │ │
     │  └────────────────────┬────────────────────────┘ │
     │                       ▼                          │
     │  ┌─────────────────────────────────────────────┐ │
     │  │ ssh_server.go ─ SSH 認證 / channel 分派      │ │
     │  └─┬────────────────────────────────────┬──────┘ │
     │    │                                    │        │
     │    ▼ (target=udpgw)                     ▼        │
     │  ┌─────────────────┐          ┌──────────────┐   │
     │  │ udpgw.go        │          │ TCP forward  │   │
     │  │ DNS 攔截 +       │          │ + dialSmart  │   │
     │  │ 透明轉發         │          └──────┬───────┘   │
     │  └────┬───────┬────┘                 │           │
     │       │       │                      │           │
     │       ▼       ▼                      ▼           │
     │   [自解析]  [udpgw         [dns.go:resolver]      │
     │            sidecar]                              │
     └──────────────────────────────────────────────────┘
                       │                  │
                       ▼                  ▼
                  外部 DNS               目標伺服器
              (8.8.8.8, 1.1.1.1)        (HTTPS / TCP)
```

### 程式碼結構

| 檔案 | 職責 |
|------|------|
| `main.go` | 程式進入點與 listener 編排 |
| `config.go` | 設定結構、env 解析、儲存/載入 |
| `traffic.go` | 流量統計 sync.Map 與持久化 |
| `session.go` | 後台登入 cookie 管理 |
| `tls.go` | 自簽憑證生成、SNI 白名單 |
| `logging.go` | 中央 log 收集器、降噪輔助 |
| `ssh_server.go` | SSH 握手、tolerantCopy、direct-tcpip |
| `dispatcher.go` | 80/443 入口分流、HTTP Upgrade 偽裝 |
| `api.go` | Admin 後台 HTTP API |
| `dns.go` | DNS 解析子系統(多 server、UDP→TCP fallback) |
| `udpgw.go` | UDPGW 協定攔截、DNS 短路 |
| `ip_tunnel.go` | IP-over-SSH 隧道(可選) |
| `nat_setup.go` | iptables NAT 與 IP forward |

---

## 快速部署

### 系統需求

- Linux (amd64 / arm64)
- Docker 20.10+ 與 Docker Compose v2
- 對外開放 port: 80, 443, 9090 (後台), 7300 (UDPGW)

### Docker Compose 部署 (推薦)

建立資料夾並寫入 `docker-compose.yml`:

```yaml
services:
  wstunnel:
    image: ghcr.io/treehd/wstunnel:latest
    container_name: wstunnel
    restart: always
    ports:
      - "80:80"
      - "443:443"
      - "9090:9090"
      - "7300:7300"
    dns:
      - 8.8.8.8
      - 1.1.1.1
    environment:
      - DNS_SERVER=8.8.8.8, 1.1.1.1:53
    volumes:
      - ./data:/app/data
    healthcheck:
      test: ["CMD", "bash", "-c", "echo > /dev/tcp/127.0.0.1/80 2>/dev/null"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 5s
```

啟動:

```bash
docker compose up -d
```

第一次啟動會在 `./data/` 自動產生 `config.json`,並隨機產生管理員密碼:

```bash
docker logs wstunnel | grep "密碼:"
```

### 後台登入

```
http://<伺服器IP>:9090/login.html
帳號: admin
密碼: (見上方 docker logs)
```

進入後台後請立即修改密碼,並依需求新增使用者帳號。

---

## 連線模式

`wstunnel-go` 同時支援多種主流的免流/穿透協定,客戶端可依環境擇一使用:

| 模式 | 入口 Port | 使用情境 |
|------|----------|---------|
| **Direct TCP** | 22 (若另開) | 標準 SSH 連線,不偽裝 |
| **HTTP Payload** | 80 | 走 HTTP Upgrade 偽裝,適合 80 埠口被劫持時 |
| **Direct TLS** | 443 | 純 TLS 加密 SSH,SNI 可任意指定 |
| **TLS + Payload** | 443 | TLS 後再做 HTTP Upgrade 偽裝(NPV Tunnel 預設) |

### 客戶端設定範例 (NPV Tunnel)

| 欄位 | 值 |
|------|-----|
| 模式 | TLS + Payload |
| Server Host | 你的伺服器 IP |
| Server Port | 443 |
| SNI | `www.cloudflare.com` (或任何允許的 SNI) |
| Payload | `GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: <CONNECT_UA>[crlf][crlf]` |
| SSH 帳密 | 後台 `accounts` 中設定的帳密 |
| UDPGW | 啟用,Address: `127.0.0.1:7300` |

### 客戶端設定範例 (HTTP Injector / HTTP Custom)

| 欄位 | 值 |
|------|-----|
| Connection Type | SSH + Payload + SSL/TLS |
| Server | `<伺服器 IP>:443` |
| SNI / SSL Host | `www.cloudflare.com` |
| Payload | `GET / HTTP/1.1[crlf]Host: [host_port][crlf]User-Agent: <CONNECT_UA>[crlf]Upgrade: websocket[crlf][crlf]` |
| SSH 帳密 | 後台 `accounts` 中設定的帳密 |

---

## DNS 與 UDPGW

這是 wstunnel-go 與其他類似專案最主要的差異點。

### 為什麼 DNS 容易出問題?

NPV Tunnel 等 TUN-mode VPN 客戶端不在本地解析 DNS,所有 DNS 查詢都是
UDP/53 封包,經由 **UDPGW** 通道送到伺服器再往外發。傳統做法把 UDPGW 流量
全交給 sidecar 的 `udpgw-server`,這帶來兩個問題:

1. **udpgw 進程死掉就全死**:主程式無法察覺,使用者只看到 NXDOMAIN
2. **機房擋 UDP/53**:udpgw 用 raw UDP 出站,被擋就完全沒退路

### wstunnel-go 的解法

主程式直接攔截 SSH `direct-tcpip` 通往 udpgw 的連線,在 SSH channel 層
解析 UDPGW frame:

- **DNS 流量** (`dst_port==53` 或帶 `FLAG_DNS`) → 由 wstunnel 自己用
  `dns.go` 的 resolver chain 解析,**完全不依賴 udpgw 進程**
- **其他 UDP** → 透明轉發給 udpgw,維持遊戲、QUIC 等其他應用可用

DNS 解析路徑:

1. 先嘗試 client 指定的 server (如 8.8.8.8:53),5 秒逾時
2. 失敗 → 退到 `globalConfig.DNSServer` (支援多 server 逗號分隔)
3. 每個 server 先 UDP 後 TCP (DNS-over-TCP 規避 UDP 封鎖)
4. 全部失敗才回應錯誤,並印出失敗分類 log

### 觀測

啟動時:

```
DNS HEALTH-CHECK: ✅ OK — probe=cloudflare.com ips=[104.16.132.229] elapsed=15ms
UDPGW HEALTH-CHECK: ✅ udpgw process is alive at 127.0.0.1:7300
```

連線時(節流為 30 秒一次):

```
UDPGW: session start user='appleme' from 220.132.29.65:54494
UDPGW DNS: ✅ working via 8.8.8.8:53 — total success=312 failed=0 (last 30s window)
```

詳細統計可透過 `GET /api/udpgw/status` 取得。

---

## 設定參考

設定檔 `data/config.json` 在第一次啟動時自動產生,所有欄位也可由環境變數覆寫。

### 主要欄位

| 欄位 | 環境變數 | 預設值 | 說明 |
|------|---------|--------|------|
| `listen_addr` | `LISTEN_ADDR` | `0.0.0.0:80` | HTTP Upgrade 入口 |
| `listen_tls_addr` | `LISTEN_TLS_ADDR` | `0.0.0.0:443` | TLS Multiplexer 入口 |
| `admin_addr` | `ADMIN_ADDR` | `0.0.0.0:9090` | 管理後台 |
| `dns_server` | `DNS_SERVER` | (空) | DNS 上游,支援逗號分隔多筆 |
| `udpgw_port` | `UDPGW_PORT` | `7300` | 本機 udpgw 進程 port |
| `connect_ua` | `CONNECT_UA` | (空) | HTTP Upgrade 必要 UA |
| `allowed_sni` | `ALLOWED_SNI` | `[]` | SNI 白名單,空陣列為全放行 |
| `handshake_timeout` | `HANDSHAKE_TIMEOUT` | `5` | 偽裝握手逾時 (秒) |
| `idle_timeout_seconds` | `IDLE_TIMEOUT_SECONDS` | `120` | SSH idle 逾時 |
| `target_connect_timeout_seconds` | `TARGET_CONNECT_TIMEOUT_SECONDS` | `10` | 目標撥號逾時 |
| `buffer_size_kb` | `BUFFER_SIZE_KB` | `32` | TCP copy buffer |
| `tolerant_copy_max_retries` | `TOLERANT_COPY_MAX_RETRIES` | `100` | 暫時性網路錯誤重試上限 |
| `traffic_save_interval_seconds` | `TRAFFIC_SAVE_INTERVAL_SECONDS` | `300` | 流量存盤間隔 |
| `default_expiry_days` | `DEFAULT_EXPIRY_DAYS` | `30` | 新帳號預設到期天數 |
| `default_limit_gb` | `DEFAULT_LIMIT_GB` | `0` | 新帳號預設流量上限 (0=不限) |

### 帳號結構

```json
{
  "accounts": {
    "user1": {
      "password": "pass1",
      "enabled": true,
      "expiry_date": "2026-12-31",
      "limit_gb": 50.0,
      "max_sessions": 3,
      "friendly_name": "User One"
    }
  }
}
```

### Debug 模式

設定 `WSTUNNEL_DEBUG=1` 啟用詳細 log,會印出:

- TLS handshake 失敗細節
- HTTP Upgrade 階段的 UA 拒絕紀錄
- tolerantCopy 的網路恢復過程
- 所有 SSH channel 分派決策

平時關閉,只在排障時暫時開啟。

---

## 管理後台

`http://<IP>:9090/`

主要面板:
- **總覽**:連線數、CPU/Memory、流量總量、運行時間
- **線上連線**:即時的使用者連線、IP、流量、剩餘額度,可手動踢除
- **帳號管理**:新增/修改/啟停/重置流量
- **系統設定**:DNS、UDPGW Port、buffer 大小、各類 timeout
- **系統日誌**:最近 200 行 log,即時更新
- **管理員密碼**:登入後可修改自身密碼

API 端點(需 cookie 認證):

| Path | Method | 用途 |
|------|--------|------|
| `/api/server_status` | GET | 系統狀態 |
| `/api/connections` | GET | 線上連線清單 |
| `/api/accounts` | GET/POST/DELETE | 帳號 CRUD |
| `/api/settings` | GET/POST | 系統設定 |
| `/api/traffic` | GET | 流量總表 |
| `/api/logs` | GET | 最近 log |
| `/api/udpgw/status` | GET | UDPGW 攔截統計 |

---

## 故障排查

### 連得上但 DNS 不通(NXDOMAIN)

依序檢查 log:

1. **DNS HEALTH-CHECK** 是否 ✅:不過則改 `DNS_SERVER` 換家
2. **UDPGW: session start** 是否出現:沒出現代表手機 App 沒啟用 UDPGW
3. **UDPGW DNS: ✅ working** 是否出現:有就代表 DNS 攔截運作中
4. 都正常仍 NXDOMAIN:檢查手機 App 是否設定錯誤的 DNS 伺服器

### TLS handshake 失敗

- 檢查客戶端是否有設定正確的 SNI
- 啟用 `WSTUNNEL_DEBUG=1` 看詳細錯誤
- 確認憑證 `cert.pem` / `key.pem` 沒被刪掉(刪了會自動重建)

### Auth 失敗

- 檢查 `data/config.json` 中 `accounts` 是否啟用 (`enabled: true`)
- 檢查到期日 (`expiry_date`) 是否已過
- 檢查流量是否已用盡

### 容器無法啟動

- 先用 `docker logs wstunnel` 看 FATAL 訊息
- 若是 port 衝突:檢查宿主機 80/443/9090/7300 是否已被佔用
- 若是 config.json 無法解析:刪除 `data/config.json` 讓系統重建

---

## 自行編譯

需要 Go 1.25+。

```bash
git clone https://github.com/TreeHD/wstunnel.git
cd wstunnel
go mod download
CGO_ENABLED=0 go build -ldflags "-s -w" -o wstunnel-go
./wstunnel-go
```

啟動後預設讀 `./data/config.json`,前端檔在 `./frontend/`。

### Docker 自行 build

```bash
docker build -t wstunnel-local .
docker run -d \
  -p 80:80 -p 443:443 -p 9090:9090 -p 7300:7300 \
  -v $(pwd)/data:/app/data \
  -e DNS_SERVER=8.8.8.8 \
  --name wstunnel wstunnel-local
```

### 開發注意事項

- 所有變數命名遵循 Go CamelCase
- 文件與 log 文字使用台灣正體中文
- 新增功能請整合既有的 `globalConfig.Accounts` 認證、`globalTraffic` 流量統計、
  `sync.WaitGroup` 優雅關閉機制
- 詳見 [`agents.md`](agents.md)

---

## 限制與已知問題

- **單機部署**:不支援多節點橫向擴展(Session、流量資料皆存在本機磁碟)
- **TUN 功能需 NET_ADMIN**:`createTunDevice()` 需要容器具備 `cap_net_admin`,
  Docker 預設不給,IP 隧道功能會自動降級停用而不影響其他模式
- **無 IPv6 出站偏好**:目前 `dialContextSmart` 預設 IPv4 優先,純 IPv6 目標
  仍可解析,但 dual-stack 時不會優先選 IPv6
- **DNSTT 為獨立映像**:DNS 隧道(Slipstream)走 `ghcr.io/treehd/wstunnel-dnstt`,
  與主程式分開部署,使用 `docker compose --profile dnstt up`
- **流量統計為 best-effort**:在程式被 SIGKILL 時最近 5 分鐘流量可能遺失
- **後台無 RBAC**:目前所有 admin 帳號權限相同,無細粒度權限控制
- **不支援憑證自動續簽**:預設使用自簽憑證,有效期 1 年,過期需自行刪除重建

---

## 授權

MIT License

歡迎提交 Issue 與 Pull Request。在貢獻 PR 前請先閱讀 [`agents.md`](agents.md)
了解專案的命名規範與貢獻指引。
