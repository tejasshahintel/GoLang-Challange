package main

import ("fmt"
		"os"
		//"reflect"
		"errors"
		"crypto/rand"
		"crypto/rsa"
		"crypto/x509"
		"encoding/pem"
)

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
		return errors.New("Invalid Iput string.Please prvide string that is less than 250 chars")
	
	}
	return nil
}

func GenerateKeys()error{

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	
	if err!= nil{
		return errors.New("Invalid Iput string.Please prvide string that is less than 250 chars")
	}
	
	fmt.Println("Generating Public Key ..")
	pubKey := key.Public()
	//fmt.Println(pubKey)
	
	//Encoding Private Key
	keyPEM := pem.EncodeToMemory(
        &pem.Block{
            Type:  "RSA PRIVATE KEY",
            Bytes: x509.MarshalPKCS1PrivateKey(key),
        },
    )
	fmt.Println(keyPEM)
	

    // Encode public key to PKCS#1 ASN.1 PEM.
    pubPEM := pem.EncodeToMemory(
        &pem.Block{
            Type:  "RSA PUBLIC KEY",
            Bytes: x509.MarshalPKCS1PublicKey(pubKey.(*rsa.PublicKey)),
        },
    )
	fmt.Println("\n Public Key:\n\n")
	fmt.Println(pubPEM)
	return nil
}
func main() {
	fmt.Println("crypto sign code challenge")

	
	fmt.Println(os.Args[0])
	//fmt.Println(reflect.TypeOf(os.Args))
	err := validateInput(os.Args)
	checkError(err)

	input := os.Args[1]
	fmt.Println(input)
	err = GenerateKeys()
	checkError(err)
	

}
