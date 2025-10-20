package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http" // [1] 新增：引入 net/http 包用于解析请求
	"strings"
	"sync/atomic"
	"io/ioutil" // [2] 新增：引入 ioutil 包用于丢弃请求体

	"golang.org/x/crypto/ssh"
)

var (
	listenAddr = flag.String("addr", ":80", "Listen address")
	socksAddr  = flag.String("socks", "127.0.0.1:1080", "Local SOCKS5 address")
	user       = flag.String("user", "a555", "SSH username")
	pass       = flag.String("pass", "a444", "SSH password")
)

var activeConn int64

// SOCKS5 connect (无任何改动)
func socks5Connect(socksAddr string, destHost string, destPort uint16) (net.Conn, error) {
	c, err := net.Dial("tcp", socksAddr)
	if err != nil { return nil, err }
	_, err = c.Write([]byte{0x05, 0x01, 0x00}); if err != nil { c.Close(); return nil, err }
	buf := make([]byte, 2); if _, err := io.ReadFull(c, buf); err != nil { c.Close(); return nil, err }
	if buf[1] != 0x00 { c.Close(); return nil, fmt.Errorf("socks5 auth failed") }
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(destHost))}; req = append(req, []byte(destHost)...); req = append(req, byte(destPort>>8), byte(destPort&0xff))
	if _, err = c.Write(req); err != nil { c.Close(); return nil, err }
	rep := make([]byte, 4); if _, err := io.ReadFull(c, rep); err != nil { c.Close(); return nil, err }
	if rep[1] != 0x00 { c.Close(); return nil, fmt.Errorf("socks5 connect failed") }
	switch rep[3] {
	case 0x01: io.CopyN(io.Discard, c, 4+2); case 0x03: alen := make([]byte, 1); io.ReadFull(c, alen); io.CopyN(io.Discard, c, int64(alen[0])+2); case 0x04: io.CopyN(io.Discard, c, 16+2)
	}
	return c, nil
}

// handleDirectTCPIP (无任何改动)
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32) {
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)
	socksConn, err := socks5Connect(*socksAddr, destHost, uint16(destPort))
	if err != nil {
		log.Printf("connect to SOCKS5 fail: %v", err)
		ch.Close()
		return
	}
	defer socksConn.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(socksConn, ch); socksConn.Close(); done <- struct{}{} }()
	go func() { io.Copy(ch, socksConn); ch.Close(); done <- struct{}{} }()
	<-done
}

// ==============================================================================
// === 核心修改点：升级 httpHandshake 函数 ===
// ==============================================================================

// [3] 新增一个结构体，用于将预读的数据和原始连接组合起来
// 这是为了解决 bufio.Reader 预读数据导致SSH握手失败的根本问题
type combinedConn struct {
	net.Conn
	reader io.Reader
}

func (c *combinedConn) Read(p []byte) (n int, err error) {
	return c.reader.Read(p)
}


// httpHandshake 现在返回一个 net.Conn，因为原始的 conn 可能已经被“包装”了
func httpHandshake(conn net.Conn) (net.Conn, error) {
	// 1. 创建临时的 bufio.Reader
	reader := bufio.NewReader(conn)

	// 2. 使用 http.ReadRequest 来健壮地解析HTTP请求
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("read http request fail: %v", err)
	}

	// 3. 丢弃请求体，防止干扰后续的SSH流
	io.Copy(ioutil.Discard, req.Body)
	req.Body.Close()

	// 4. 执行 User-Agent 认证
	if strings.Contains(req.UserAgent(), "26.4.0") {
		// 认证通过，返回模拟的 WebSocket 升级响应
		_, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		if err != nil {
			return nil, fmt.Errorf("write http response fail: %v", err)
		}

		// 5. [关键] 将 bufio.Reader 中可能预读的SSH数据和原始连接组合成一个新的数据流
		// 这是最稳健的做法，可以防止数据丢失或损坏
		finalConn := &combinedConn{
			Conn:   conn,
			reader: io.MultiReader(reader, conn),
		}
		
		return finalConn, nil
	}
	
	return nil, fmt.Errorf("invalid user-agent")
}

// main (只有非常小的改动)
func main() {
	flag.Parse()

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == *user && string(p) == *pass { return nil, nil }
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	
	_, priv, err := ed25519.GenerateKey(rand.Reader); if err != nil { log.Fatalf("generate host key fail: %v", err) }
	privateKey, err := ssh.NewSignerFromKey(priv); if err != nil { log.Fatalf("create signer fail: %v", err) }
	config.AddHostKey(privateKey)

	l, err := net.Listen("tcp", *listenAddr); if err != nil { log.Fatalf("listen fail: %v", err) }
	log.Printf("Listening on %s, forwarding to SOCKS5 %s", *listenAddr, *socksAddr)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept fail: %v", err)
			continue
		}

		go func(c net.Conn) {
			atomic.AddInt64(&activeConn, 1)
			defer atomic.AddInt64(&activeConn, -1)

			// [4] 修改调用方式
			// httpHandshake 现在返回一个新的 conn 对象
			handshakedConn, err := httpHandshake(c)
			if err != nil {
				log.Printf("http handshake failed: %v", err)
				c.Close()
				return
			}
			log.Printf("Phase 1 OK: HTTP handshake passed, waiting SSH payload")

			// [5] 将握手后返回的 conn 对象传递给 ssh.NewServerConn
			sshConn, chans, reqs, err := ssh.NewServerConn(handshakedConn, config)
			if err != nil {
				log.Printf("ssh handshake failed: %v", err)
				c.Close()
				return
			}
			defer sshConn.Close()
			log.Printf("Phase 2: SSH handshake success from %s", sshConn.RemoteAddr())
			go ssh.DiscardRequests(reqs)

			for newChan := range chans {
				if newChan.ChannelType() != "direct-tcpip" {
					newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip allowed")
					continue
				}
				ch, _, err := newChan.Accept()
				if err != nil { log.Printf("accept channel fail: %v", err); continue }

				var payload struct {
					Host       string
					Port       uint32
					OriginAddr string
					OriginPort uint32
				}
				if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
					log.Printf("bad payload: %v", err)
					ch.Close()
					continue
				}

				go handleDirectTCPIP(ch, payload.Host, payload.Port)
			}

		}(conn)
	}
}
