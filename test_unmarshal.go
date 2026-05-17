package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
)

func main() {
	extraData := ssh.Marshal(struct {
		Host           string
		Port           uint32
		OriginatorIP   string
		OriginatorPort uint32
	}{
		"google.com",
		443,
		"127.0.0.1",
		12345,
	})

	var payload struct {
		Host string
		Port uint32
	}
	err := ssh.Unmarshal(extraData, &payload)
	fmt.Printf("Error: %v\n", err)
	fmt.Printf("Host: %q, Port: %d\n", payload.Host, payload.Port)
}
