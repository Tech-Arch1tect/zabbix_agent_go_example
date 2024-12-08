package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

var ZabbixHeader = []byte("ZBXD\x01")

func queryZabbixAgent(addr, key, pskIdentity, psk string) (string, error) {
	var conn net.Conn
	var err error

	if pskIdentity != "" && psk != "" {
		pskBytes, err := decodePSK(psk)
		if err != nil {
			return "", fmt.Errorf("failed to decode PSK: %w", err)
		}

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			PSK: func(hint []byte) ([]byte, error) {
				return pskBytes, nil
			},
			PSKIdentity: func() []byte {
				return []byte(pskIdentity)
			},
			InsecureSkipVerify: true,
		}

		conn, err = tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return "", fmt.Errorf("failed to connect over PSK TLS: %w", err)
		}
	} else {
		conn, err = net.Dial("tcp", addr)
		if err != nil {
			return "", fmt.Errorf("failed to connect to agent: %w", err)
		}
	}
	defer conn.Close()

	payload := []byte(key)
	payloadLength := uint64(len(payload))

	buffer := bytes.NewBuffer(ZabbixHeader)
	if err := binary.Write(buffer, binary.LittleEndian, payloadLength); err != nil {
		return "", fmt.Errorf("failed to write payload length: %w", err)
	}
	buffer.Write(payload)

	if _, err := conn.Write(buffer.Bytes()); err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if n < len(ZabbixHeader) || !bytes.HasPrefix(response[:n], ZabbixHeader) {
		return "", errors.New("invalid response header")
	}

	result := string(response[len(ZabbixHeader):n])
	return result, nil
}

func decodePSK(psk string) ([]byte, error) {
	// not fully implemented
	if psk == "" {
		return nil, errors.New("empty PSK")
	}
	return []byte(psk), nil
}

func main() {
	addr := "127.0.0.1:10050"
	key := "system.cpu.load[all,avg1]"

	pskIdentity := "my-psk-identity"
	psk := "raw-psk"

	result, err := queryZabbixAgent(addr, key, pskIdentity, psk)
	if err != nil {
		fmt.Printf("Error querying Zabbix agent: %v\n", err)
		return
	}

	fmt.Printf("Zabbix agent response: %s\n", result)
}
