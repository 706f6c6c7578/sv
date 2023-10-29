package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"bytes"
	"strings"
	"strconv"
)

const signatureMarker = "----Ed25519 Signature----"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sv [genkey|sign|verify] [message file] [key file] [-l lineLength]")
		return
	}

	command := os.Args[1]

	switch command {
	case "genkey":
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatalf("Failed to generate key pair: %v", err)
		}

		publicKeyHex := hex.EncodeToString(publicKey)
		privateKeyHex := hex.EncodeToString(privateKey)

		publicKeyFile := "pubme"
		privateKeyFile := "secme"

		err = ioutil.WriteFile(publicKeyFile, []byte(publicKeyHex), 0644)
		if err != nil {
			log.Fatalf("Failed to save public key: %v", err)
		}

		err = ioutil.WriteFile(privateKeyFile, []byte(privateKeyHex), 0644)
		if err != nil {
			log.Fatalf("Failed to save private key: %v", err)
		}

		fmt.Println("Key pair generated and saved in pubkey and privkey")

	case "sign":
		if len(os.Args) < 4 {
			fmt.Println("Usage: sv sign [message file] [private key file] [-l lineLength]")
			return
		}

		messageFile := os.Args[2]
		keyFile := os.Args[3]
		lineLength := 0 // Default to one long line

		// Check if the user provided a line length as an integer using the -l option
		for i := 4; i < len(os.Args); i++ {
			if os.Args[i] == "-l" && i+1 < len(os.Args) {
				providedLineLength, err := strconv.Atoi(os.Args[i+1])
				if err != nil {
					log.Fatalf("Invalid line length: %v", err)
				}
				lineLength = providedLineLength
			}
		}

		privateKeyBytes, err := ioutil.ReadFile(keyFile)
		if err != nil {
			log.Fatalf("Failed to read private key file: %v", err)
		}

		privateKey, err := hex.DecodeString(string(privateKeyBytes))
		if err != nil {
			log.Fatalf("Failed to decode private key: %v", err)
		}

		messageBytes, err := ioutil.ReadFile(messageFile)
		if err != nil {
			log.Fatalf("Failed to read the message file: %v", err)
		}

		// Check for EOF
		if len(messageBytes) > 0 && messageBytes[len(messageBytes)-1] != '\n' {
			messageBytes = append(messageBytes, '\n')
		}

		signature := signMessage(privateKey, messageBytes)
		signatureHex := hex.EncodeToString(signature)

		// Split the signature into lines based on the specified line length or use a single line
		var signatureLines []byte
		if lineLength > 0 {
			signatureLines = splitString(signatureHex, lineLength)
		} else {
			signatureLines = []byte(signatureHex)
		}

		// Append the signature lines with the marker
		messageWithSignature := append(messageBytes, []byte(signatureMarker+"\n")...)
		messageWithSignature = append(messageWithSignature, []byte(signatureLines)...)

		err = ioutil.WriteFile(messageFile, messageWithSignature, 0644)
		if err != nil {
			log.Fatalf("Failed to save message with signature: %v", err)
		}

		fmt.Printf("Signature: %s\n", signatureHex)

	case "verify":
		if len(os.Args) < 4 {
			fmt.Println("Usage: sv verify [message file] [public key file]")
			return
		}

		messageFile := os.Args[2]
		keyFile := os.Args[3]

		publicKeyBytes, err := ioutil.ReadFile(keyFile)
		if err != nil {
			log.Fatalf("Failed to read public key file: %v", err)
		}

		publicKey, err := hex.DecodeString(string(publicKeyBytes))
		if err != nil {
			log.Fatalf("Failed to decode public key: %v", err)
		}

		messageWithSignature, err := ioutil.ReadFile(messageFile)
		if err != nil {
			log.Fatalf("Failed to read the message with signature: %v", err)
		}

		// Check for the signature marker
		parts := bytes.SplitN(messageWithSignature, []byte(signatureMarker), 2)
		if len(parts) != 2 {
			log.Fatalf("Invalid message format: missing signature marker")
		}

		messageBytes := parts[0]
		signatureHex := bytes.TrimSpace(parts[1])

		// Remove line breaks and spaces from the signature
		signatureHex = bytes.ReplaceAll(signatureHex, []byte("\n"), []byte(""))
		signatureHex = bytes.ReplaceAll(signatureHex, []byte(" "), []byte(""))

		valid := verifySignature(publicKey, signatureHex, messageBytes)
		if valid {
			fmt.Println("Signature is valid.")
		} else {
			fmt.Println("Signature is not valid.")
		}
	}
}

func signMessage(privateKey []byte, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

func verifySignature(publicKey []byte, signatureHex []byte, message []byte) bool {
	signature, err := hex.DecodeString(string(signatureHex))
	if err != nil {
		log.Fatalf("Failed to decode signature: %v", err)
	}

	return ed25519.Verify(publicKey, message, signature)
}

func splitString(s string, lineLength int) []byte {
	length := len(s)
	parts := []string{}

	for i := 0; i < length; i += lineLength {
		end := i + lineLength
		if end > length {
			end = length
		}
		parts = append(parts, s[i:end])
	}

	return []byte(strings.Join(parts, "\n"))
}

