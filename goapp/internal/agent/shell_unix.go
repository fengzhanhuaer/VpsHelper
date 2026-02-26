//go:build !windows

package agent

import (
	"io"
	"log"
	"os"
	"os/exec"

	"github.com/creack/pty"
	"github.com/hashicorp/yamux"
)

func handleAgentShell(stream *yamux.Stream, prefixReader io.Reader) {
	defer stream.Close()

	sh := os.Getenv("SHELL")
	if sh == "" {
		sh = "/bin/sh" // Default fallback
		if _, err := os.Stat("/bin/bash"); err == nil {
			sh = "/bin/bash"
		}
	}

	cmd := exec.Command(sh)
	// Try creating a PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Printf("[Agent] PTY Shell error: %v, fallback to dumb shell", err)
		cmd = exec.Command("sh")
		cmd.Stdin = io.MultiReader(prefixReader, stream)
		cmd.Stdout = stream
		cmd.Stderr = stream
		_ = cmd.Run()
		return
	}
	defer ptmx.Close()

	// Copy data to and from PTY
	go func() {
		_, _ = io.Copy(ptmx, io.MultiReader(prefixReader, stream))
	}()
	_, _ = io.Copy(stream, ptmx)

	_ = cmd.Wait()
}
