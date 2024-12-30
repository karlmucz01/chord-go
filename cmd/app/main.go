package main

import (
	"fmt"

	"github.com/karlmucz01/chord-go/pkg/utils"
)

func main() {
	x := utils.IdentifierFromString("hello")
	fmt.Println(x)
}
