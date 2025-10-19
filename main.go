// ssh_relay.go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

var (
	listenAddr = flag.String("addr", ":2222", "SSH listen address")
	socksAddr  = flag.String("socks", "127.0.0.1:1080", "Local SOCKS5 address")
	user       = flag.String("user", "a555", "SSH username")
	pass       = flag.String("pass", "a444", "SSH password")
)

var activeConn int64

func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32) {
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)

	// 连接本地 SOCKS5
	socksConn, err := net.Dial("tcp", *socksAddr)
	if err != nil {
		log.Printf("connect to SOCKS5 fail: %v", err)
		ch.Close()
		return
	}
	defer socksConn.Close()

	// 双向透传
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(socksConn, ch)
		socksConn.Close()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(ch, socksConn)
		ch.Close()
		done <- struct{}{}
	}()
	<-done
}

func main() {
	flag.Parse()

	// SSH Server 配置
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == *user && string(p) == *pass {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}

	// 生成 Ed25519 host key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate host key fail: %v", err)
	}
	privateKey, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatalf("create signer fail: %v", err)
	}
	config.AddHostKey(privateKey)

	// 监听端口
	l, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen fail: %v", err)
	}
	log.Printf("Listening on %s, forwarding to SOCKS5 %s", *listenAddr, *socksAddr)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept fail: %v", err)
			continue
		}

		go func(c net.Conn) {
			sshConn, chans, reqs, err := ssh.NewServerConn(c, config)
			if err != nil {
				log.Printf("ssh handshake fail: %v", err)
				c.Close()
				return
			}
			defer sshConn.Close()
			log.Printf("new SSH conn from %s", sshConn.RemoteAddr())
			go ssh.DiscardRequests(reqs)

			for newChan := range chans {
				if newChan.ChannelType() != "direct-tcpip" {
					newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip allowed")
					continue
				}
				ch, _, err := newChan.Accept()
				if err != nil {
					log.Printf("accept channel fail: %v", err)
					continue
				}

				// 解析目标地址
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
