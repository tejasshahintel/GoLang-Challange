package main

import ("fmt"
		"os"
		//"reflect"
		"errors"
		//"crypto/ecdsa"
		//"math/rand"
		"crypto"
		"crypto/rand"
		"crypto/rsa"
		"crypto/x509"
		"crypto/sha256"
		"encoding/pem"
		"encoding/base64"
		"encoding/json"
		//"encoding/asn1"
		"io/ioutil"
		//b64 "encoding/base64"
)

type outputData struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	PubKey    string `json:"pubkey"`

func checkError(errStr error){
	if errStr!= nil{
		fmt.Println(errStr)
		os.Exit(1)
	}
}
//Method to validate inputs. Checks if string is provided. Also, checks for the length of the string
func validateInput(args []string)(error){
	if len(os.Args)!=2{
		return errors.New("Invalid number of inputs")
		//os.Exit(1)
	}
		
	if len(os.Args[1]) > 250 {
		return errors.New("Invalid Input string.Please prvide string that is less than 250 chars")
	}
	return nil
}
func perfSignature(input, pubKey string,privKey *rsa.PrivateKey)(outputData, error){
	
	var output outputData
	data := []byte(input)
	fmt.Println(data)
	hash := sha256.Sum256(data)
	fmt.Printf("%x", hash[:])
	fmt.Printf("data = %T\n", data)
	fmt.Printf("hash = %T\n", hash)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return output, err
	}
	fmt.Printf("signature: %v\n", signature)
	fmt.Printf("Type signature: %T\n", signature)
	encodedSign := base64.StdEncoding.EncodeToString([]byte(signature))
	//fmt.Printf("encodedSign: %v\n", encodedSign)
	
	output.Message = input
	output.Signature = encodedSign
	output.PubKey = pubKey
	fmt.Println(output)
	return output, nil
}

func createFileforKey(keyObj []uint8, filename string) error {

	if err := ioutil.WriteFile(filename, keyObj, 0700); err != nil {
        return errors.New("Not able to wrrite key to the file"+filename)
    }
	return nil
}

func generateKeys()(*rsa.PrivateKey, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err!= nil{
		return nil, "",errors.New("Invalid Iput string.Please prvide string that is less than 250 chars")
	}
	
	pubKey := key.Public()
	
	//Encoding Private Key
	keyPEM := &pem.Block{
            Type:  "RSA PRIVATE KEY",
            Bytes: x509.MarshalPKCS1PrivateKey(key)}
    
	encodedPrivKey := pem.EncodeToMemory(keyPEM)
	
    // Encode public key to PKCS#1 ASN.1 PEM.
    pubPEM := &pem.Block{
            Type:  "RSA PUBLIC KEY",
            Bytes: x509.MarshalPKCS1PublicKey(pubKey.(*rsa.PublicKey))}
    
	encodedPubKey := pem.EncodeToMemory(pubPEM)
	fmt.Println("\n Public Key:\n")
	fmt.Println(encodedPubKey)

	// Write private key to file.
    filename := "key"
	err = createFileforKey(encodedPrivKey,filename+".rsa")
	checkError(err)

	err = createFileforKey(encodedPubKey,filename+".rsa.pub")
	checkError(err)
	return key, string(encodedPubKey), nil
}

func main() {
	
	var (
		privateKey *rsa.PrivateKey
		publicKey  string
	)
	
	err := validateInput(os.Args)
	checkError(err)

	input := os.Args[1]
	fmt.Println(input)
	privateKey, publicKey, err = generateKeys()
	
}
