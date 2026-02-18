package config

import (
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	BaseDir           string
	DataDir           string
	DBPath            string
	TemplatesDir      string
	ListenAddr        string
	SessionKey        string
	ReadHeaderTimeout time.Duration
}

const (
	UnifiedDBName   = "VpsHelper.db"
	UnifiedD1DBName = "VpsHelper_db"
)

func Load() Config {
	baseDir, _ := os.Getwd()

	dataDir := os.Getenv("VPSHELPER_DATA_DIR")
	if dataDir == "" {
		dataDir = filepath.Join(baseDir, "..", "userdata")
	}

	templatesDir := os.Getenv("VPSHELPER_TEMPLATES_DIR")
	if templatesDir == "" {
		templatesDir = filepath.Join(baseDir, "templates")
	}

	listenAddr := os.Getenv("VPSHELPER_LISTEN")
	if listenAddr == "" {
		listenAddr = ":15018"
	}

	sessionKey := os.Getenv("VPSHELPER_SESSION_KEY")
	if sessionKey == "" {
		sessionKey = "change-this-key"
	}

	return Config{
		BaseDir:           baseDir,
		DataDir:           dataDir,
		DBPath:            filepath.Join(dataDir, UnifiedDBName),
		TemplatesDir:      templatesDir,
		ListenAddr:        listenAddr,
		SessionKey:        sessionKey,
		ReadHeaderTimeout: 10 * time.Second,
	}
}
