package main

import ("fmt"
		"os"
		//"reflect"
		"errors"
)

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
func main() {
	fmt.Println("crypto sign code challenge")

	
	fmt.Println(os.Args[0])
	//fmt.Println(reflect.TypeOf(os.Args))
	err := validateInput(os.Args)
	if err!= nil{
		fmt.Println(err)
		os.Exit(1)
	}
	input := os.Args[1]
	fmt.Println(input)

}
