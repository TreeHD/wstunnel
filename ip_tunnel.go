// ip_tunnel.go
package main

import (
	"encoding/binary"
	"fmt" // <-- 注意：fmt 在这里是需要的
	"io"
	"log"
	"net"
	"sync"

	"github.com/songgao/water"
	"golang.org/x/crypto/ssh"
)

var tunInterface *water.Interface
var tunMutex sync.Mutex // 保护TUN接口的并发读写

// createTunDevice 创建并配置一个TUN虚拟网卡
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
	
	// 这个函数的实现有待完善，暂时只做最简单的转发
	// go readFromTunAndDistribute()

	return nil
}

// handleIPTunnel 处理来自客户端的IP隧道流量
func handleIPTunnel(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("IP Tunnel: New session for %s", clientKey)
	defer log.Printf("IP Tunnel: Session for %s closed", clientKey)
	defer ch.Close()

	done := make(chan struct{})

	// Goroutine 1: 从SSH信道读取数据，写入TUN设备
	go func() {
		defer close(done) // 任何一端断开，都关闭另一端
		for {
			lenBytes := make([]byte, 2)
			if _, err := io.ReadFull(ch, lenBytes); err != nil {
				return
			}
			dataLen := binary.BigEndian.Uint16(lenBytes)

			if dataLen > 4096 {
				log.Printf("IP Tunnel: Received oversized IP packet (%d bytes) from %s, closing session.", dataLen, clientKey)
				return
			}

			ipPacket := make([]byte, dataLen)
			if _, err := io.ReadFull(ch, ipPacket); err != nil {
				return
			}
			
			tunMutex.Lock()
			_, err := tunInterface.Write(ipPacket)
			tunMutex.Unlock()
			if err != nil {
				log.Printf("IP Tunnel: Error writing to TUN device: %v", err)
				return
			}
		}
	}()

	// Goroutine 2: 从TUN设备读取数据，写入SSH信道
	packet := make([]byte, 4096)
	for {
		tunMutex.Lock()
		n, err := tunInterface.Read(packet)
		tunMutex.Unlock()
		
		if err != nil {
			log.Printf("IP Tunnel: Error reading from TUN device: %v", err)
			return
		}

		if n > 0 {
			lenBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBytes, uint16(n))
			
			if _, err := ch.Write(lenBytes); err != nil {
				return
			}
			if _, err := ch.Write(packet[:n]); err != nil {
				return
			}
		}
	}
}

// readFromTunAndDistribute 的复杂性在于需要将包路由回正确的 ssh.Channel
// 暂时不使用全局 reader，而是为每个会话创建一个 reader
func readFromTunAndDistribute() {
	// This function can be used for a more advanced implementation
	// where a single goroutine reads from TUN and dispatches packets
	// to the correct client channels based on a session map.
	// For now, we use a simpler model in handleIPTunnel.
}
