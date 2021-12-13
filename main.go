package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

//output data that will be written in JSON file
type outputData struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	PubKey    string `json:"pubkey"`
}

func checkError(errStr error) {
	if errStr != nil {
		fmt.Println(errStr)
		os.Exit(1)
	}
}

/*Method to validate inputs. Checks if string is provided. 
Also, checks for the length of the string*/
func validateInput(args []string) error {
	if len(os.Args) != 2 {
		return errors.New("Invalid number of inputs")
		//os.Exit(1)
	}

	if len(os.Args[1]) > 250 {
		return errors.New("Invalid Input string.Please prvide string that is less than 250 chars")
	}
	return nil
}

func perfSignature(input, pubKey string, privKey *rsa.PrivateKey) (outputData, error) {

	var output outputData

	/*Perform Hashing using SHA256 hash algorithms
	Referenced from: https://pkg.go.dev/crypto/sha256 */
	data := []byte(input)
	hash := sha256.Sum256(data)
	
	//Referenced from https://pkg.go.dev/crypto/rsa#SignPKCS1v15
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return output, err
	}

	encodedSign := base64.StdEncoding.EncodeToString([]byte(signature))

	/*Storing the results in outputData struct to be 
	written in JSON*/
	output.Message = input
	output.Signature = encodedSign
	output.PubKey = pubKey
	return output, nil
}

/*Method to write the keys into filename. This creates .rsa and .rsa.pub files
for keys*/
func createFileforKey(keyObj []uint8, filename string) error {

	if err := ioutil.WriteFile(filename, keyObj, 0700); err != nil {
		return errors.New("Not able to wrrite key to the file" + filename)
	}
	return nil
}

/*Referenced from:
https://pkg.go.dev/crypto/rsa#GenerateKey 
https://stackoverflow.com/questions/64104586/use-golang-to-get-rsa-key-the-same-way-openssl-genrsa */
func generateKeys() (*rsa.PrivateKey, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, "", errors.New("Invalid Iput string.Please prvide string that is less than 250 chars")
	}

	pubKey := key.Public()

	//Converting an RSA private key to PKCS #1, ASN.1 DER form
	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key)}

	encodedPrivKey := pem.EncodeToMemory(keyPEM)

	// Encode public key to PKCS#1 ASN.1 PEM.
	pubPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pubKey.(*rsa.PublicKey))}

	encodedPubKey := pem.EncodeToMemory(pubPEM)

	// Write private key to file.
	filename := "key"
	err = createFileforKey(encodedPrivKey, filename+".rsa")
	checkError(err)

	err = createFileforKey(encodedPubKey, filename+".rsa.pub")
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

	privateKey, publicKey, err = generateKeys()
	output, err := perfSignature(input, publicKey, privateKey)
	
	//Converting it to JSON
	outJSON, err := json.MarshalIndent(output, "", "    ")
	err = ioutil.WriteFile("output.json", outJSON, 0644)
	fmt.Println("\n\n\nOutput JSON File:\n", string(outJSON))

}
