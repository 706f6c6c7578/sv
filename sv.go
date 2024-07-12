package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

const signatureMarker = "----Ed25519 Signature----"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: sv <gk[-w]|s|v> [options] [key file]\n")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "gk":
		generateKeyPair()
	case "s":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: sv s <private key file> < infile > outfile\n")
			os.Exit(1)
		}
		signMessage(os.Args[2])
	case "v":
		if len(os.Args) != 2 {
			fmt.Fprintf(os.Stderr, "Usage: sv v < infile\n")
			os.Exit(1)
		}
		verifyMessage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		os.Exit(1)
	}
}

func generateKeyPair() {
	writeToFile := false
	if len(os.Args) > 2 && os.Args[2] == "-w" {
		writeToFile = true
	}

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	publicKeyHex := hex.EncodeToString(publicKey)
	privateKeyHex := hex.EncodeToString(privateKey)

	if writeToFile {
		err = ioutil.WriteFile("pubkey", []byte(publicKeyHex), 0644)
		if err != nil {
			log.Fatalf("Failed to write public key to file: %v", err)
		}

		err = ioutil.WriteFile("seckey", []byte(privateKeyHex), 0600)
		if err != nil {
			log.Fatalf("Failed to write private key to file: %v", err)
		}

		fmt.Println("Key pair generated and saved in 'pubkey' and 'seckey' files.")
	} else {
		fmt.Println(publicKeyHex)
		fmt.Println(privateKeyHex)
	}
}

func signMessage(keyFile string) {
	privateKeyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("Failed to read private key file: %v", err)
	}

	privateKey, err := hex.DecodeString(strings.TrimSpace(string(privateKeyBytes)))
	if err != nil {
		log.Fatalf("Failed to decode private key: %v", err)
	}

	var messageBytes []byte
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == signatureMarker {
			break
		}
		messageBytes = append(messageBytes, []byte(line)...)
		messageBytes = append(messageBytes, '\r', '\n')
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading input: %v", err)
	}

	// Remove trailing CRLF if present
	messageBytes = bytes.TrimSuffix(messageBytes, []byte("\r\n"))

	signature := ed25519.Sign(privateKey, messageBytes)
	signatureHex := hex.EncodeToString(signature)

	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	publicKeyHex := hex.EncodeToString(publicKey)

	fmt.Print(string(messageBytes))
	fmt.Printf("\r\n%s\r\n", signatureMarker)
	fmt.Printf("%s\r\n", signatureHex[:64])
	fmt.Printf("%s\r\n", signatureHex[64:])
	fmt.Printf("%s\r\n", publicKeyHex)
}

func verifyMessage() {
	scanner := bufio.NewScanner(os.Stdin)
	var messageBytes []byte
	var signatureHex, publicKeyHex string
	inSignature := false

	for scanner.Scan() {
		line := scanner.Text()
		if line == signatureMarker {
			inSignature = true
			continue
		}
		if inSignature {
			if signatureHex == "" {
				signatureHex = line
			} else if len(signatureHex) == 64 {
				signatureHex += line
			} else {
				publicKeyHex = line
				break
			}
		} else {
			messageBytes = append(messageBytes, scanner.Bytes()...)
			messageBytes = append(messageBytes, '\r', '\n')
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading input: %v", err)
	}

	// Remove trailing CRLF if present
	messageBytes = bytes.TrimSuffix(messageBytes, []byte("\r\n"))

	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		log.Fatalf("Failed to decode public key: %v", err)
	}

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		log.Fatalf("Failed to decode signature: %v", err)
	}

	if ed25519.Verify(publicKey, messageBytes, signature) {
		fmt.Println("Signature is valid.")
	} else {
		fmt.Println("Signature is not valid.")
	}
}
