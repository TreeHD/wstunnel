// Package iptun 提供 IP-over-SSH 隧道功能。
//
// 整合了三個面向:
//   1. TUN 裝置建立與 NAT 設定 (原 ip_tunnel.go + nat_setup.go)
//   2. Client session 註冊表 (原 session_manager.go)
//   3. 中央封包分發器,根據 dst IP 路由到對應 client
//
// 注意:此 package 需要容器具備 NET_ADMIN cap,否則 createTunDevice 會失敗,
// 此時呼叫端應 graceful degrade,不影響其他功能。
package iptun

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/songgao/water"
	"golang.org/x/crypto/ssh"
)

var (
	tunInterface *water.Interface
	tunMutex    sync.Mutex // 保護 TUN 接口的並發寫入
)

// CreateTunDevice 建立 tun0,設定 IP 與 NAT。
// 失敗時呼叫端應視為「IP 隧道功能停用」,不應 fatal。
func CreateTunDevice() error {
	const (
		ifaceAddr = "10.0.0.1/24"
	)
	cfg := water.Config{
		DeviceType: water.TUN,
	}

	ifce, err := water.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	if err := runIP("link", "set", "dev", ifce.Name(), "up"); err != nil {
		return fmt.Errorf("failed to set TUN device up: %w", err)
	}
	if err := runIP("addr", "add", ifaceAddr, "dev", ifce.Name()); err != nil {
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

// HandleChannel 處理一條 SSH ip-tunnel channel 的雙向轉發。
func HandleChannel(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("IP Tunnel: New session for %s. Waiting for first packet to determine client IP.", clientKey)
	defer log.Printf("IP Tunnel: Session for %s closed", clientKey)
	defer ch.Close()

	packetChan := make(chan []byte, 100)
	sess := &clientSession{packetChan: packetChan}
	var clientTunIP string
	defer func() {
		if clientTunIP != "" {
			manager.Unregister(clientTunIP)
		}
	}()

	done := make(chan struct{})

	// TUN -> SSH
	go func() {
		for ipPacket := range packetChan {
			if _, err := ch.Write(ipPacket); err != nil {
				log.Printf("IP Tunnel: Error writing to SSH channel for %s: %v", clientKey, err)
				return
			}
		}
	}()

	// SSH -> TUN
	go func() {
		defer close(done)
		packet := make([]byte, 4096)
		isRegistered := false
		for {
			n, err := ch.Read(packet)
			if err != nil {
				return
			}
			if n > 0 {
				ipPacket := packet[:n]
				if !isRegistered {
					if len(ipPacket) < 20 {
						continue
					}
					srcIP := net.IP(ipPacket[12:16]).String()
					if srcIP == "0.0.0.0" {
						log.Printf("WARN: Received packet with invalid source IP 0.0.0.0 from %s. Ignoring.", clientKey)
						continue
					}
					clientTunIP = srcIP
					manager.Register(clientTunIP, sess)
					isRegistered = true
				}
				tunMutex.Lock()
				_, writeErr := tunInterface.Write(ipPacket)
				tunMutex.Unlock()
				if writeErr != nil {
					log.Printf("IP Tunnel: Error writing to TUN device: %v", writeErr)
					return
				}
			}
		}
	}()

	<-done
}

// ReadAndDistribute 是中央分發器,在獨立 goroutine 中跑。
// 從 TUN 讀 IP 封包,依目的 IP 找對應的 client session 並送過去。
func ReadAndDistribute() {
	log.Println("Central packet distributor started. Reading from TUN device...")
	packet := make([]byte, 4096)
	for {
		n, err := tunInterface.Read(packet)
		if err != nil {
			log.Printf("Central distributor: Error reading from TUN device: %v", err)
			continue
		}
		if n == 0 || n < 20 {
			continue
		}
		destIP := net.IP(packet[16:20]).String()
		sess := manager.GetSession(destIP)
		if sess != nil {
			cp := make([]byte, n)
			copy(cp, packet[:n])
			select {
			case sess.packetChan <- cp:
			default:
				log.Printf("WARN: Client channel for %s is full. Packet dropped.", destIP)
			}
		}
	}
}

// --- session manager ---

type clientSession struct {
	packetChan chan<- []byte
}

type sessionManager struct {
	sync.RWMutex
	sessions map[string]*clientSession
}

var manager = &sessionManager{
	sessions: make(map[string]*clientSession),
}

func (sm *sessionManager) Register(clientIP string, s *clientSession) {
	sm.Lock()
	defer sm.Unlock()
	log.Printf("Session Manager: Registering session for IP %s", clientIP)
	sm.sessions[clientIP] = s
}

func (sm *sessionManager) Unregister(clientIP string) {
	sm.Lock()
	defer sm.Unlock()
	if clientIP != "" {
		log.Printf("Session Manager: Unregistering session for IP %s", clientIP)
		delete(sm.sessions, clientIP)
	}
}

func (sm *sessionManager) GetSession(clientIP string) *clientSession {
	sm.RLock()
	defer sm.RUnlock()
	return sm.sessions[clientIP]
}

// --- nat / ip helpers ---

func runIP(args ...string) error {
	cmd := exec.Command("ip", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command 'ip %s' failed: %v, output: %s", strings.Join(args, " "), err, string(output))
	}
	return nil
}

func enableIPForwarding() error {
	log.Println("Enabling kernel IP forwarding...")
	return ioutil.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

func setupNAT(physicalInterfaceName string) error {
	log.Printf("Setting up iptables NAT rule for outgoing interface %s...", physicalInterfaceName)
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables command not found, please install it")
	}

	checkArgs := []string{"-t", "nat", "-C", "POSTROUTING", "-o", physicalInterfaceName, "-j", "MASQUERADE"}
	if err := exec.Command("iptables", checkArgs...).Run(); err == nil {
		log.Println("iptables NAT rule already exists.")
		return nil
	}

	addArgs := []string{"-t", "nat", "-A", "POSTROUTING", "-o", physicalInterfaceName, "-j", "MASQUERADE"}
	cmd := exec.Command("iptables", addArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add iptables rule: %v, output: %s", err, string(output))
	}
	log.Println("iptables NAT rule added successfully.")
	return nil
}

func getDefaultInterface() (string, error) {
	cmd := exec.Command("ip", "-4", "route", "show", "default")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("could not get default route: %v, output: %s", err, string(output))
	}
	fields := strings.Fields(string(output))
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "eth0", fmt.Errorf("could not parse default interface, defaulting to 'eth0'")
}
