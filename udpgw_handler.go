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

// clientState 用于存储每个客户端会话的状态.
type clientState struct {
	udpConn    net.PacketConn
	targetAddr *net.UDPAddr
	sshChan    ssh.Channel
	done       chan struct{}
	key        string
}

// ClientManager 定义
type ClientManager struct {
	sync.RWMutex
	clients map[string]*clientState
}

var clientManager = &ClientManager{
	clients: make(map[string]*clientState),
}

func (cm *ClientManager) Add(key string, state *clientState) {
	cm.Lock()
	defer cm.Unlock()
	cm.clients[key] = state
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
	log.Printf("UdpGw Proxy: New session for %s", clientKey)
	
	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Printf("UdpGw Proxy: Failed to listen on UDP for %s: %v", clientKey, err)
		ch.Close()
		return
	}

	state := &clientState{
		udpConn: udpConn,
		sshChan: ch,
		done:    make(chan struct{}),
		key:     clientKey,
	}
	clientManager.Add(clientKey, state)

	defer func() {
		log.Printf("UdpGw Proxy: Session for %s closed", clientKey)
		clientManager.Delete(clientKey)
		// ch.Close() 由 handleSshConnection 的 defer 保证
	}()

	// Goroutine 1: 从SSH读取、解析、发送
	go func() {
		defer close(state.done)
		for {
			lenBytes := make([]byte, 2)
			if _, err := io.ReadFull(ch, lenBytes); err != nil {
				log.Printf("UdpGw Proxy: Error reading length from %s: %v", clientKey, err)
				return
			}
			dataLen := binary.BigEndian.Uint16(lenBytes)
			
			if dataLen == 0 { continue }
			if dataLen > 4096 {
				log.Printf("UdpGw Proxy: Invalid data length %d from %s, closing.", dataLen, clientKey)
				return
			}
			
			fullData := make([]byte, dataLen)
			if _, err := io.ReadFull(ch, fullData); err != nil {
				log.Printf("UdpGw Proxy: Error reading payload from %s: %v", clientKey, err)
				return
			}
			
			log.Printf("DEBUG: Received frame from %s. Length: %d, Type: %d", clientKey, dataLen, fullData[0])

			packetType := fullData[0]
			payload := fullData[1:]

			if packetType != 0 { // 控制帧
				addrStr := string(payload)
				if !strings.Contains(addrStr, ":") {
					addrStr = fmt.Sprintf("%s:7300", addrStr)
				}
				destAddr, err := net.ResolveUDPAddr("udp", addrStr)
				if err != nil {
					// 控制帧解析失败，只打印日志，不关闭连接，等待下一个正确的控制帧
					log.Printf("UdpGw Proxy: Failed to resolve destination '%s' for %s: %v. Waiting for next valid control frame.", addrStr, clientKey, err)
					continue
				}
				state.targetAddr = destAddr
				log.Printf("UdpGw Proxy: Set new UDP destination to %s for %s", destAddr, clientKey)

			} else { // 数据帧
				if state.targetAddr == nil {
					continue
				}
				udpConn.WriteTo(payload, state.targetAddr)
			}
		}
	}()
	
	// Goroutine 2: 从UDP套接字读取返回，封装并发送回客户端
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
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return 
			}
			
			udpRemote := remote.(*net.UDPAddr)
			remoteIP := udpRemote.IP.To4()
			if remoteIP == nil { continue }
			
			payload := buf[:n]
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
