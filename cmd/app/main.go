package main

import (
	"fmt"

	"github.com/karlmucz01/chord-go/pkg/utils"
)

func main() {

	x := utils.IdentifierFromStringSha1("karl")
	fmt.Println(x)
}
