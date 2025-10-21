// udpgw_handler.go
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// clientState 用于存储每个客户端会话的状态
type clientState struct {
	udpConn    net.PacketConn
	targetAddr *net.UDPAddr
	dnsAddr    *net.UDPAddr
	sshChan    ssh.Channel
	done       chan struct{}
	key        string
}

// [核心修正] 定义一个具名的 ClientManager 类型
type ClientManager struct {
	sync.RWMutex
	clients map[string]*clientState
}

// [核心修正] 创建一个具名类型的全局实例
var clientManager = &ClientManager{
	clients: make(map[string]*clientState),
}

// [核心修正] 方法现在附加到 *ClientManager 类型上
func (cm *ClientManager) Add(key string, state *clientState) {
	cm.Lock()
	defer cm.Unlock()
	cm.clients[key] = state
}

func (cm *ClientManager) Get(key string) *clientState {
	cm.RLock()
	defer cm.RUnlock()
	return cm.clients[key]
}

func (cm *ClientManager) Delete(key string) {
	cm.Lock()
	defer cm.Unlock()
	if state, ok := cm.clients[key]; ok {
		state.udpConn.Close()
		delete(cm.clients, key)
	}
}

// handleUdpGw 的最终实现，增加了调试日志和容错
func handleUdpGw(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("Hybrid UDP Proxy: New session for %s", clientKey)
	defer log.Printf("Hybrid UDP Proxy: Session for %s closed", clientKey)
	defer ch.Close()

	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Printf("Hybrid UDP Proxy: Failed to listen on UDP for %s: %v", clientKey, err)
		return
	}
	
	defaultDNSAddr, _ := net.ResolveUDPAddr("udp", "8.8.8.8:53")

	state := &clientState{
		udpConn: udpConn,
		dnsAddr: defaultDNSAddr,
		sshChan: ch,
		done:    make(chan struct{}),
		key:     clientKey,
	}
	clientManager.Add(clientKey, state) // 现在可以正确调用
	defer clientManager.Delete(clientKey) // 现在可以正确调用

	// Goroutine 1: 从SSH读取、智能解析、发送
	go func() {
		defer close(state.done)
		header := make([]byte, 2)
		for {
			if _, err := io.ReadFull(ch, header); err != nil {
				return
			}
			firstTwoBytes := binary.BigEndian.Uint16(header)

			if firstTwoBytes > 0 && firstTwoBytes < 2048 {
				// UdpGw 协议
				dataLen := firstTwoBytes
				fullData := make([]byte, dataLen)
				if _, err := io.ReadFull(ch, fullData); err != nil { return }
				
				packetType := fullData[0]
				payload := fullData[1:]

				if packetType != 0 { // 控制帧
					addrStr := string(payload)
					if !strings.Contains(addrStr, ":") {
						addrStr = fmt.Sprintf("%s:7300", addrStr)
					}
					destAddr, err := net.ResolveUDPAddr("udp", addrStr)
					if err != nil {
						log.Printf("Hybrid UDP Proxy: Failed to resolve UdpGw destination '%s': %v", addrStr, err)
						continue
					}
					state.targetAddr = destAddr
					log.Printf("Hybrid UDP Proxy: Set UdpGw destination to %s for %s", destAddr, clientKey)
				} else { // 数据帧
					if state.targetAddr == nil { continue }
					udpConn.WriteTo(payload, state.targetAddr)
				}
			} else {
				// 原始DNS包
				restOfPacket := make([]byte, 1024)
				n, err := ch.Read(restOfPacket)
				if err != nil { return }
				
				dnsPacket := append(header, restOfPacket[:n]...)
				log.Printf("Hybrid UDP Proxy: Detected raw DNS query (len %d)", len(dnsPacket))
				udpConn.WriteTo(dnsPacket, state.dnsAddr)
			}
		}
	}()
	
	// Goroutine 2: 从UDP套接字读取返回
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-state.done:
				return
			default:
			}
			
			udpConn.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, remote, err := udpConn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() { continue }
				return
			}
			
			udpRemote := remote.(*net.UDPAddr)
			remoteIP := udpRemote.IP.To4()
			if remoteIP == nil { continue }
			
			payload := buf[:n]

			// 简化回包逻辑：假设客户端都能处理UdpGw格式的回包
			totalLen := 4 + 2 + len(payload)
			frame := make([]byte, 2+totalLen)
			binary.BigEndian.PutUint16(frame[0:2], uint16(totalLen))
			copy(frame[2:6], remoteIP)
			binary.BigEndian.PutUint16(frame[6:8], uint16(udpRemote.Port))
			copy(frame[8:], payload)
			if _, err := ch.Write(frame); err != nil {
				return
			}
		}
	}()

	<-state.done
}
