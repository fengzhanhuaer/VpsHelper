package shell

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
)

const HistoryLimit = 2048

var ownerSafe = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

func historyPath(dataDir, owner string) string {
	safe := ownerSafe.ReplaceAllString(owner, "_")
	return filepath.Join(dataDir, "shell_history_"+safe+".json")
}

func LoadHistory(dataDir, owner string) []string {
	p := historyPath(dataDir, owner)
	b, err := os.ReadFile(p)
	if err != nil {
		return []string{}
	}

	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return []string{}
	}

	if len(out) > HistoryLimit {
		out = out[len(out)-HistoryLimit:]
	}
	return out
}

func SaveHistory(dataDir, owner string, commands []string) {
	if len(commands) > HistoryLimit {
		commands = commands[len(commands)-HistoryLimit:]
	}
	b, err := json.Marshal(commands)
	if err != nil {
		return
	}
	_ = os.WriteFile(historyPath(dataDir, owner), b, 0o644)
}

func AppendHistory(dataDir, owner, cmd string) {
	if cmd == "" {
		return
	}
	history := LoadHistory(dataDir, owner)
	if len(history) == 0 || history[len(history)-1] != cmd {
		history = append(history, cmd)
	}
	SaveHistory(dataDir, owner, history)
}
