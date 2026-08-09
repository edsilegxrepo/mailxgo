// Package main - mailxgo CLI Application Executable Entry Point
//
// OBJECTIVES:
// Serve as the standalone executable entry point binary for the mailxgo command-line application.
//
// CORE COMPONENTS:
// - main: Entry point function forwarding process arguments (os.Args[1:]) to mailxgo.RunCLI.
//
// FUNCTIONALITY & DATA FLOW:
// Process Invocation -> os.Args[1:] -> mailxgo.RunCLI -> CLI Flag Engine & Dispatch Routine.
package main

import (
	"os"

	mailxgo "github.com/edsilegxrepo/mailxgo"
)

// main is the CLI binary entry point forwarding command-line arguments to mailxgo.RunCLI.
func main() {
	mailxgo.RunCLI(os.Args[1:])
}
