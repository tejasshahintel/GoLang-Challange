package main

import (
	//"fmt"
	//"os"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
)

const keys = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEA8ksuZU2CwPWUOknmK/IDRRJ9fGfMf/GUwkslr01Q1T5XpPcez7G4
CAco1wsEw8AV65iC/1Y32Oo9efX3gQTSowguWsJLUBvLK4Uk0elSv4liIDnytuE6
WbgHusbpEoUCdF7/3bqac2I7AyRtZkmeuUOsH4EdDxmSL10blSple2FU7k5bjICx
kvO5Fh26Jks/vsNzUfHSM+XDMENXmPXkufiCg9rfila2TsdIOCf3coZ2zC4vGTk4
YShj1Ru16yYYfy3FlG6lrMsWKTg2ZIwHmgS0BlxsaBC/IXzbUDOsQXkVJEm4TPHn
Lx6DYG3suPBEijsr6G2njskkMgbjCHlIDKPv52cW1/9w+hJu7wRAo2DxQ9E0qFbz
ZQeP1VPTZc4adDIoPCGkP5ewp30ph6esmS02i0oafaBSE+60PuK2/gqen//ec7aF
9jQ8klRBDdyOSpnaDDMGedFI/HSUKMVeqWKA6Rz6vgYOArPmK3viE6LrRNYVolr4
osGF8tYKO+a6XVhdPBREYdFDsAu6a/CTJvqJCRq+mtqxsai9yiyod2I3OAWXIEvr
6mmPaX6FcRdeWFu3DMd8LUxZtp3nxrPswHDTNJsRUXlvBKxRMPEcBf9lfIBOgNlj
r9SHuRWk1hBlBySOvhBX/D8HqDZzNQUeJoehcwZUsfiddeRTOU/kSucCAwEAAQ==
-----END RSA PUBLIC KEY-----
`

func getkeys() (*rsa.PrivateKey, string) {
	block, rest := pem.Decode([]byte(keys))

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	checkError(err)

	publicKey := string(rest)

	return privateKey, publicKey
}
func TestSignature(t *testing.T) {

	privKey, pubKey := getkeys()

	input := "Test Application"
	data := []byte(input)
	signature, err := perfSignature(input, pubKey, privKey)
	if err != nil {
		t.Errorf("Error signing message: %v", err)
	}
	decodedSign, err := base64.StdEncoding.DecodeString(signature.Signature)
	if err != nil {
		t.Errorf("Error signing message: %v", err)
	}
	//fmt.Printf("Decoded:%T", decodedSign)

	hash := sha256.Sum256(data)
	err1 := rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA256, hash[:], decodedSign)
	if err1 != nil {
		t.Errorf("Error signing message: %v", err)
	}

	var out outputData
	outJSON, err := json.MarshalIndent(signature, "", "    ")
	err = json.Unmarshal([]byte(outJSON), &out)
	if err != nil {
		t.Errorf("Error unmarshaling json: %v", err)
	}
}
