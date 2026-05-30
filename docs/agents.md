# WSTunnel-Go 開發與架構指南 (給未來的 Agent)

哈囉!未來的 AI Agent,當你被派來修改或擴充這個專案時,請務必先閱讀這封指南,了解本專案的核心架構以及我們的開發習慣。

## 1. 核心觀念 (Architecture Overview)

這是一個高度客製化的「代理 (Free-Flow Proxy)」與多重通訊協定分發器:

* **目錄結構** (依 [golang-standards/project-layout](https://github.com/golang-standards/project-layout) 慣例):
  * `cmd/wstunnel/`: 程式進入點(薄殼),只做 wiring 與 listener 啟動
  * `internal/`: 不對外公開的子套件,Go compiler 強制只能本 module import
    * `config`: Config 結構、env、save/load
    * `logging`: log 收集器、降噪輔助、`WSTUNNEL_DEBUG` 開關
    * `traffic`: 流量統計與持久化
    * `session`: 後台 admin login cookie
    * `tlsutil`: 自簽憑證生成 + SNI 白名單
    * `dnsx`: DNS resolver chain + 多 server failover + UDP→TCP fallback
    * `proxy`: 上游 SOCKS5/HTTP CONNECT (帶 Auth) + DialTarget 統一出口
    * `iptun`: IP-over-SSH 隧道(TUN/iptables/session manager)
    * `udpgw`: UDPGW 攔截 + DNS 短路
    * `sshsrv`: SSH 握手、tolerantCopy、direct-tcpip
    * `dispatcher`: 80/443 入口分流 + HTTP Upgrade 偽裝
    * `adminapi`: 9090 後台所有 HTTP handler
  * `web/`: 控制面板的網頁前端 (HTML)
  * `build/`: Docker 相關檔案
    * `Dockerfile`, `Dockerfile.dnstt`: 主程式與 DNSTT 隧道映像建置
    * `entrypoint.sh`: 容器入口,啟動 udpgw (loopback) + 主程式
    * `entrypoint.dnstt.sh`: DNSTT 容器入口
  * `docs/`: 開發文件(本檔)
  * `docker-compose.yml`: 部署設定(刻意保留 repo root,符合慣例)

* **package singleton 模式**:每個 package 內部仍保留 singleton(如 `config.current`、`traffic.store`),透過 exported getter/setter 對外暴露。這是刻意選擇的最小改動策略,避免改成 dependency injection 的大量改寫成本。
* **UDP 支援 (UDPGW)**:採用 `tun2proxy` 專案的 `udpgw-server`。**故意只綁 127.0.0.1 並不對外公開 port**,避免被當匿名 UDP 出口代理。
* **DNS 解析**:wstunnel 主程式直接攔截 SSH `direct-tcpip` 通往 udpgw 的連線(`internal/udpgw`),DNS 查詢由主程式自行解析(`internal/dnsx`),不依賴外部 udpgw 進程。
* **DNS 隧道 (DNSTT)**:內建 [Slipstream-rust](https://github.com/Mygod/slipstream-rust) 支援,獨立 image。
* **流量統計**:`internal/traffic` 用 sync.Map + atomic 累加,定期存盤。
* **Port 複用**:`443` 入口在 `internal/dispatcher` 做 Peek 判斷 SSH-direct vs HTTP-Upgrade 偽裝。**修改這一塊時請特別注意不要破壞原有的 Peek 邏輯。**


## 2. 開發習慣與指導原則

### 2.1 修改與編譯
這個專案依賴 `go mod` 進行套件管理,若你新增或修改了 import,請務必執行:
```bash
go mod tidy
CGO_ENABLED=0 go build -ldflags "-s -w" -o wstunnel-go ./cmd/wstunnel
```
*註:`build/Dockerfile` 內的 Builder 為 `golang:1.25-alpine`。本機開發需 Go 1.25+。*

### 2.2 命名風格與用語
* **變數名稱**:遵守標準的 Go CamelCase。
* **package 命名**:全小寫、單字、避免與 stdlib 撞名(我們把 `tls` 改成 `tlsutil`、`dns` 改成 `dnsx`)。
* **文件或對話用語**:預設使用**台灣正體中文用語**:
  * 「伺服器」 (不要用 服務器)
  * 「設定檔」 (不要用 配置文件)
  * 「支援」 (不要用 支持)
  * 「連線」 (不要用 鏈接)
  * 「預設」 (不要用 默認)

### 2.3 功能擴充注意事項
1. **package 邊界**:新功能優先放進對應的 `internal/<pkg>/`。新增 package 時要避免循環依賴,依賴方向為 `dispatcher → sshsrv → {dnsx, proxy, udpgw, iptun, traffic}`,leaf package(`config`/`logging`/`traffic`/`session`/`tlsutil`)不應 import 上層。
2. **認證整合**:重複利用 `config.Get().Accounts` 機制,所有帳號狀態統一控制。讀寫請走 `config.Get().Lock`。
3. **流量統計**:任何代理功能消耗了流量都應該透過 `traffic.AddSent(t, n)` / `traffic.AddReceived(t, n)`。
4. **撥號統一走 `proxy.DialTarget`**:所有出站 TCP 連線都應透過此 helper,才能尊重「上游 Proxy 鏈接」設定。
5. **優雅關閉**:`cmd/wstunnel/main.go` 已捕捉 SIGINT/SIGTERM。若新增 server 常駐邏輯,記得加入 `sync.WaitGroup`。

## 3. Docker 化部署與多架構
我們使用 Docker 的多階段建置 (Multi-stage build):
1. `go-builder`: 編譯 `./cmd/wstunnel` (Alpine)
2. `udpgw-downloader`: 根據 `TARGETARCH` (amd64/arm64) 下載對應的 `tun2proxy` 專案 `udpgw-server` **gnu** 二進位檔
3. `runner`: 最終運行的 **Debian** 鏡像,包含所有二進位檔與 `build/entrypoint.sh`

GitHub Actions 拆成 `wstunnel-publish.yml` 與 `dnstt-publish.yml` 兩條 pipeline,只在對應檔案變更時觸發,arm64 使用原生 runner 避免 QEMU 模擬。

-- 祝你開發順利!

