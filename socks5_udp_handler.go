// socks5_udp_handler.go
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

// targetAddrMap 用于存储每个客户端会话的目标UDP地址
var targetAddrMap = struct {
	sync.RWMutex
	m map[string]*net.UDPAddr
}{
	m: make(map[string]*net.UDPAddr),
}

func setTargetAddr(clientKey string, addr *net.UDPAddr) {
	targetAddrMap.Lock()
	defer targetAddrMap.Unlock()
	targetAddrMap.m[clientKey] = addr
}

func getTargetAddr(clientKey string) *net.UDPAddr {
	targetAddrMap.RLock()
	defer targetAddrMap.RUnlock()
	return targetAddrMap.m[clientKey]
}

func delTargetAddr(clientKey string) {
	targetAddrMap.Lock()
	defer targetAddrMap.Unlock()
	delete(targetAddrMap.m, clientKey)
}

// handleSocks5UDP 的最终实现，兼容 UdpGw 协议
func handleSocks5UDP(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("UdpGw Proxy: New session for %s", clientKey)
	defer log.Printf("UdpGw Proxy: Session for %s closed", clientKey)
	defer ch.Close()
	defer delTargetAddr(clientKey)

	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Printf("UdpGw Proxy: Failed to listen on UDP port for %s: %v", clientKey, err)
		return
	}
	defer udpConn.Close()

	done := make(chan struct{})

	// Goroutine 1: 从SSH读取、解析、发送
	go func() {
		defer close(done)
		for {
			// UdpGw 协议: [2字节长度][1字节类型][数据]
			
			// 1. 读取2字节长度
			lenBytes := make([]byte, 2)
			if _, err := io.ReadFull(ch, lenBytes); err != nil {
				return
			}
			dataLen := binary.BigEndian.Uint16(lenBytes)

			if dataLen == 0 {
				continue
			}

			// 2. 读取数据 (包含1字节的类型 + 负载)
			fullData := make([]byte, dataLen)
			if _, err := io.ReadFull(ch, fullData); err != nil {
				return
			}

			// 3. 解析类型和负载
			packetType := fullData[0]
			payload := fullData[1:]

			if packetType == 0 { // 普通UDP数据包
				destAddr := getTargetAddr(clientKey)
				if destAddr == nil {
					log.Printf("UdpGw Proxy: Received data from %s but destination is not set.", clientKey)
					continue
				}
				if _, err := udpConn.WriteTo(payload, destAddr); err != nil {
					// 忽略错误
				}
			} else { // 控制包，用于设置目标地址
				addrStr := string(payload)
				if !strings.Contains(addrStr, ":") {
					addrStr = fmt.Sprintf("%s:7300", addrStr) // UdpGw 的默认端口
				}

				destAddr, err := net.ResolveUDPAddr("udp", addrStr)
				if err != nil {
					log.Printf("UdpGw Proxy: Failed to resolve destination '%s' for %s: %v", addrStr, clientKey, err)
					return // 控制包解析失败，通常意味着协议错误，关闭连接
				}
				setTargetAddr(clientKey, destAddr)
				log.Printf("UdpGw Proxy: Set new UDP destination to %s for %s", destAddr, clientKey)
			}
		}
	}()
	
	// Goroutine 2: 从UDP套接字读取返回，封装并发送回客户端
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			default:
			}
			
			udpConn.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, remote, err := udpConn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				ch.Close()
				return
			}
			
			udpRemote := remote.(*net.UDPAddr)
			remoteIP := udpRemote.IP.To4()
			if remoteIP == nil {
				continue // 只处理IPv4
			}
			
			// 封装回包: [2字节总长][4字节源IP][2字节源端口][数据]
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

	<-done
}
