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

func handleUdpGw(ch ssh.Channel, remoteAddr net.Addr) {
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
			lenBytes := make([]byte, 2)
			if _, err := io.ReadFull(ch, lenBytes); err != nil {
				return
			}
			dataLen := binary.BigEndian.Uint16(lenBytes)
			if dataLen == 0 { continue }
			if dataLen > 4096 {
				log.Printf("UdpGw Proxy: Invalid data length %d from %s", dataLen, clientKey)
				return
			}
			fullData := make([]byte, dataLen)
			if _, err := io.ReadFull(ch, fullData); err != nil {
				return
			}
			
			packetType := fullData[0]
			payload := fullData[1:]

			if packetType == 0 {
				destAddr := getTargetAddr(clientKey)
				if destAddr == nil {
					continue
				}
				udpConn.WriteTo(payload, destAddr)
			} else {
				addrStr := string(payload)
				if !strings.Contains(addrStr, ":") {
					addrStr = fmt.Sprintf("%s:7300", addrStr)
				}
				destAddr, err := net.ResolveUDPAddr("udp", addrStr)
				if err != nil {
					log.Printf("UdpGw Proxy: Failed to resolve destination '%s' for %s: %v", addrStr, clientKey, err)
					return
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

	<-done
}
