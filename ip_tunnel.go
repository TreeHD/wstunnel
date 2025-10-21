// ip_tunnel.go
package main

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/songgao/water"
	"golang.org/x/crypto/ssh"
)

var tunInterface *water.Interface
var tunMutex sync.Mutex // 仅用于保护TUN接口的并发写入

// createTunDevice 函数保持不变，这里省略以保持简洁
func createTunDevice() error {
	const (
		ifaceName = "tun0"
		ifaceAddr = "10.0.0.1/24"
	)
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = ifaceName
	ifce, err := water.New(config)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	if err := runIPCommand("link", "set", "dev", ifce.Name(), "up"); err != nil {
		return fmt.Errorf("failed to set TUN device up: %w", err)
	}
	if err := runIPCommand("addr", "add", ifaceAddr, "dev", ifce.Name()); err != nil {
		return fmt.Errorf("failed to set TUN device IP: %w", err)
	}
	if err := enableIPForwarding(); err != nil {
		log.Printf("WARN: Failed to enable IP forwarding: %v. NAT might not work.", err)
	}
	defaultIface, err := getDefaultInterface()
	if err != nil {
		log.Printf("WARN: Could not detect default network interface: %v. You may need to set the iptables rule manually.", err)
	} else {
		if err := setupNAT(defaultIface); err != nil {
			log.Printf("WARN: Failed to set up iptables NAT rule for interface %s: %v.", defaultIface, err)
		}
	}
	log.Printf("TUN device %s created and configured at %s", ifce.Name(), ifaceAddr)
	tunInterface = ifce
	return nil
}

// handleIPTunnel 处理来自客户端的IP隧道流量
func handleIPTunnel(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("IP Tunnel: New session for %s. Waiting for first packet to determine client IP.", clientKey)
	defer log.Printf("IP Tunnel: Session for %s closed", clientKey)
	defer ch.Close()

	// 为这个客户端创建一个带缓冲的channel，用于接收从TUN来的包
	packetChan := make(chan []byte, 100)
	session := &clientSession{packetChan: packetChan}

	// 这个变量将存储客户端在TUN网络中的IP地址
	var clientTunIP string
	// 使用defer确保无论函数如何退出，会话都会被注销
	defer func() {
		sessionManager.Unregister(clientTunIP)
	}()

	done := make(chan struct{})

	// Goroutine 1: 从自己的packet channel读取数据，写入SSH信道 (TUN -> SSH)
	go func() {
		for packet := range packetChan {
			// 直接将原始IP包写入SSH channel
			if _, err := ch.Write(packet); err != nil {
				log.Printf("IP Tunnel: Error writing to SSH channel for %s: %v", clientKey, err)
				return
			}
		}
	}()

	// Goroutine 2: 从SSH信道读取数据，写入TUN设备 (SSH -> TUN)
	go func() {
		defer close(done) // 此goroutine退出时，关闭done channel通知主goroutine

		packet := make([]byte, 4096)
		isRegistered := false

		for {
			// 直接从SSH channel读取一个原始IP包
			n, err := ch.Read(packet)
			if err != nil {
				// 任何读取错误（包括EOF）都意味着连接已关闭
				return
			}

			if n > 0 {
				// --- 动态识别并注册客户端IP ---
				if !isRegistered {
					if n < 20 {
						continue // 包太小，无法解析IP
					}
					// 从客户端发来的第一个IP包中，提取其源IP地址
					// IPv4包的第12到15字节是源地址
					srcIP := net.IP(packet[12:16]).String()
					clientTunIP = srcIP // 存储IP以供defer注销时使用
					sessionManager.Register(clientTunIP, session)
					isRegistered = true
				}

				// 将数据包写入全局TUN设备，加锁以防止并发写入冲突
				tunMutex.Lock()
				_, writeErr := tunInterface.Write(packet[:n])
				tunMutex.Unlock()
				if writeErr != nil {
					log.Printf("IP Tunnel: Error writing to TUN device: %v", writeErr)
					return
				}
			}
		}
	}()

	// 等待任一方向的连接关闭
	<-done
}
