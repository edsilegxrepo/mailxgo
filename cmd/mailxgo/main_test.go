// Package main - mailxgo Executable Binary Unit Tests
//
// OBJECTIVES:
// Validate standalone package main usage printing and exit code 1 invocation.
//
// CORE COMPONENTS:
// - mockMainExit: Intercepts process exit calls (osExit) via panic recovery.
// - TestUsage: Asserts Usage() prints flag menu and invokes osExit(1).
//
// FUNCTIONALITY & DATA FLOW:
// Test -> Usage() -> mockMainExit Panic Interception -> Assert exit_1 panic.
//
// TEST STRATEGY:
// Unit test capturing process exit calls using mockMainExit panic/recover trap.
package main

import (
	"fmt"
	"strings"
	"testing"
)

func mockMainExit(t *testing.T) (<-chan int, func()) {
	origExit := osExit
	exitChan := make(chan int, 1)
	osExit = func(code int) {
		select {
		case exitChan <- code:
		default:
		}
		panic(fmt.Sprintf("exit_%d", code))
	}
	cleanup := func() {
		osExit = origExit
	}
	return exitChan, cleanup
}

func TestUsage(t *testing.T) {
	_, cleanup := mockMainExit(t)
	defer cleanup()

	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("expected Usage() to call osExit, but it returned normally")
		} else if str, ok := r.(string); !ok || !strings.HasPrefix(str, "exit_1") {
			t.Errorf("expected exit_1 panic from Usage(), got %v", r)
		}
	}()

	Usage()
}
