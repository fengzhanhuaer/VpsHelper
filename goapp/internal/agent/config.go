package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	Host   string `json:"host"`
	Secret string `json:"secret"`
}

func GetConfigPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "vpsprobe.json"
	}
	return filepath.Join(filepath.Dir(exePath), "vpsprobe.json")
}

func LoadConfig() (Config, error) {
	var cfg Config
	data, err := os.ReadFile(GetConfigPath())
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

func SaveConfig(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// Write with 0600 permissions for security since it contains the secret
	return os.WriteFile(GetConfigPath(), data, 0600)
}
