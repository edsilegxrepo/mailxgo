package main

import (
	"os"

	mailxgo "github.com/edsilegxrepo/mailxgo"
)

func main() {
	mailxgo.RunCLI(os.Args[1:])
}
