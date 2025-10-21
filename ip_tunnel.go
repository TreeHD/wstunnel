// ip_tunnel.go
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/songgao/water"
	"golang.org/x/crypto/ssh"
)

var tunInterface *water.Interface

// createTunDevice 创建并配置一个TUN虚拟网卡
func createTunDevice() error {
	// 您可以自定义TUN设备的名称和IP
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

	// 使用 ip 命令为虚拟网卡配置IP地址并启动
	if err := runIPCommand("link", "set", "dev", ifce.Name(), "up"); err != nil {
		return fmt.Errorf("failed to set TUN device up: %w", err)
	}
	if err := runIPCommand("addr", "add", ifaceAddr, "dev", ifce.Name()); err != nil {
		return fmt.Errorf("failed to set TUN device IP: %w", err)
	}
	
	// 开启IP转发
	if err := enableIPForwarding(); err != nil {
		log.Printf("WARN: Failed to enable IP forwarding: %v. NAT might not work.", err)
	}

	// 设置NAT规则 (将从tun0出去的流量进行源地址伪装)
	// 这需要服务器上有 iptables
	if err := setupNAT(ifce.Name()); err != nil {
		log.Printf("WARN: Failed to set up iptables NAT rule: %v. Outgoing traffic might not work. %v", ifce.Name(), err)
	}


	log.Printf("TUN device %s created and configured at %s", ifce.Name(), ifaceAddr)
	tunInterface = ifce
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
		defer func() {
			close(done)
		}()
		for {
			// 读取2字节长度头
			lenBytes := make([]byte, 2)
			if _, err := io.ReadFull(ch, lenBytes); err != nil {
				return
			}
			dataLen := binary.BigEndian.Uint16(lenBytes)

			// 读取IP包
			ipPacket := make([]byte, dataLen)
			if _, err := io.ReadFull(ch, ipPacket); err != nil {
				return
			}
			
			// 写入TUN设备
			tunInterface.Write(ipPacket)
		}
	}()

	// Goroutine 2: 从TUN设备读取数据，写入SSH信道
	// 这个goroutine在整个程序生命周期中只需要一个
	// 但为了简化会话管理，我们为每个连接都启动一个
	packet := make([]byte, 2048) // MTU
	for {
		select {
		case <-done:
			return
		default:
			n, err := tunInterface.Read(packet)
			if err != nil {
				return
			}
			if n > 0 {
				// 在IP包前加上2字节长度头
				lenBytes := make([]byte, 2)
				binary.BigEndian.PutUint16(lenBytes, uint16(n))
				
				// 先写长度，再写数据
				ch.Write(lenBytes)
				ch.Write(packet[:n])
			}
		}
	}
}
