//go:build windows

package agent

import (
	"io"
	"log"
	"os/exec"

	"github.com/hashicorp/yamux"
)

func handleAgentShell(stream *yamux.Stream, prefixReader io.Reader) {
	defer stream.Close()

	cmd := exec.Command("cmd.exe")
	
	// Create pipes or simple assignments for dumb shell mode on Windows
	cmd.Stdin = io.MultiReader(prefixReader, stream)
	cmd.Stdout = stream
	cmd.Stderr = stream

	if err := cmd.Run(); err != nil {
		log.Printf("[Agent] Windows dumb shell error: %v", err)
	}
}
