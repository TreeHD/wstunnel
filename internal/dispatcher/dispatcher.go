// Package dispatcher 處理 80/443 入口分流與 HTTP Upgrade 偽裝握手。
package dispatcher

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"wstunnel/internal/config"
	"wstunnel/internal/logging"
	"wstunnel/internal/sshsrv"
	"wstunnel/internal/tlsutil"
)

// DispatchTLS 是 443 TLS 入口的智慧分發器。
//
// 流程:
//  1. 完成 TLS handshake,讀出 SNI
//  2. SNI 過濾(若白名單啟用)
//  3. Peek 8 bytes 判斷:
//     "SSH-2.0" 開頭 → 直接走 SSH
//     其他 → 視為 HTTP,執行 Upgrade 握手後再走 SSH
func DispatchTLS(c net.Conn, sshCfg *ssh.ServerConfig) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("FATAL: Panic recovered during dispatch for %s: %v", c.RemoteAddr(), r)
		}
		c.Close()
	}()

	tlsConn, ok := c.(*tls.Conn)
	if !ok {
		log.Printf("System: Dispatcher expected a TLS connection, but got something else.")
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		if logging.DebugEnabled {
			log.Printf("System: TLS handshake failed for %s: %v", c.RemoteAddr(), err)
		}
		return
	}

	sni := tlsConn.ConnectionState().ServerName
	if !tlsutil.SNIAllowed(sni) {
		log.Printf("System: Denied connection from %s due to invalid SNI: '%s'", c.RemoteAddr(), sni)
		return
	}

	reader := bufio.NewReader(c)
	peekedBytes, err := reader.Peek(8)
	if err != nil {
		return
	}

	if bytes.HasPrefix(peekedBytes, []byte("SSH-2.0")) {
		if logging.DebugEnabled {
			log.Printf("System: Detected direct SSH connection via TLS for %s (SNI: %s)", c.RemoteAddr(), sni)
		}
		time.Sleep(500 * time.Millisecond)
		sshsrv.HandleConnection(c, reader, sshCfg)
		return
	}

	if logging.DebugEnabled {
		log.Printf("System: Detected HTTP-based connection via TLS for %s (SNI: %s), attempting Upgrade.",
			c.RemoteAddr(), sni)
	}

	if !readUpgradeHandshake(c, reader, "TLS") {
		return
	}

	time.Sleep(500 * time.Millisecond)

	finalReader := drainBuffered(c, reader)
	sshsrv.HandleConnection(c, finalReader, sshCfg)
}

// HandleHTTPUpgrade 是 80 (純 HTTP) 入口。
// 純 HTTP 入口必須完成 Upgrade 偽裝才會接 SSH;反覆收到不合法 UA 的請求會回 200 OK 維持假象。
func HandleHTTPUpgrade(c net.Conn, sshCfg *ssh.ServerConfig) {
	defer c.Close()

	reader := bufio.NewReader(c)
	if !readUpgradeHandshake(c, reader, "port 80") {
		return
	}

	time.Sleep(500 * time.Millisecond)

	finalReader := drainBuffered(c, reader)
	sshsrv.HandleConnection(c, finalReader, sshCfg)
}

// readUpgradeHandshake 反覆讀 HTTP request,直到看到帶有正確 UA 的 Upgrade 請求。
// where 用於 log 區分入口(TLS / port 80)。
// 回傳 true 代表握手成功並已寫出 101;false 代表已斷線或逾時。
func readUpgradeHandshake(c net.Conn, reader *bufio.Reader, where string) bool {
	cfg := config.Get()
	cfg.Lock.RLock()
	timeoutDuration := time.Duration(cfg.HandshakeTimeout) * time.Second
	expectedUA := cfg.ConnectUA
	cfg.Lock.RUnlock()

	for {
		if err := c.SetReadDeadline(time.Now().Add(timeoutDuration)); err != nil {
			return false
		}

		req, err := http.ReadRequest(reader)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if logging.DebugEnabled {
					log.Printf("System: Timeout waiting for valid HTTP Upgrade on %s for %s", where, c.RemoteAddr())
				}
			}
			return false
		}
		io.Copy(ioutil.Discard, req.Body)
		req.Body.Close()

		if strings.Contains(req.UserAgent(), expectedUA) {
			_, err := c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
			if err != nil {
				return false
			}
			return true
		}

		if logging.DebugEnabled {
			log.Printf("System: Ignored invalid HTTP request on %s from %s (UA: %s)",
				where, c.RemoteAddr(), req.UserAgent())
		}
		c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\nOK"))
	}
}

// drainBuffered 把 bufio.Reader 中已預讀但尚未消費的資料黏回原 conn 之前。
func drainBuffered(c net.Conn, reader *bufio.Reader) io.Reader {
	if n := reader.Buffered(); n > 0 {
		preReadData := make([]byte, n)
		if _, err := io.ReadFull(reader, preReadData); err != nil {
			log.Printf("System: Failed to drain buffered data for %s: %v", c.RemoteAddr(), err)
			return c
		}
		return io.MultiReader(bytes.NewReader(preReadData), c)
	}
	return c
}
