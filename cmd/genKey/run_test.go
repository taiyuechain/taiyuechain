package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/docker/docker/pkg/reexec"
	"github.com/taiyuechain/taiyuechain/internal/cmdtest"
)

type testGenkey struct {
	*cmdtest.TestCmd
}

// spawns ethkey with the given command line args.
func runGenkey(t *testing.T, args ...string) *testGenkey {
	tt := new(testGenkey)
	tt.TestCmd = cmdtest.NewTestCmd(t, tt)
	tt.Run("genkey-test", args...)
	return tt
}

func TestMain(m *testing.M) {
	// Run the app if we've been exec'd as "genkey-test" in runGenkey.
	reexec.Register("genkey-test", func() {
		if err := app.Run(os.Args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	})
	// check if we have been reexec'd
	if reexec.Init() {
		return
	}
	os.Exit(m.Run())
}
