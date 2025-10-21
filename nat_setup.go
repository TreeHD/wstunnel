// nat_setup.go
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"
)

func runIPCommand(args ...string) error {
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
	// 检查iptables命令是否存在
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables command not found, please install it")
	}
	
	// 使用 -C (check) 来避免重复添加规则
	checkArgs := []string{"-t", "nat", "-C", "POSTROUTING", "-o", physicalInterfaceName, "-j", "MASQUERADE"}
	checkCmd := exec.Command("iptables", checkArgs...)
	if err := checkCmd.Run(); err == nil {
		log.Println("iptables NAT rule already exists.")
		return nil
	}
	
	// 添加规则
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
