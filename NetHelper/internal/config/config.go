package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the application configuration
type Config struct {
	ServerUrl string `json:"server_url"`
	SecretKey string `json:"secret_key"`
}

var (
	configFilePath string
)

func init() {
	// Determine the path to the executable
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("Error getting executable path: %v\n", err)
		return
	}
	exeDir := filepath.Dir(exePath)

	// Create the data directory if it doesn't exist
	dataDir := filepath.Join(exeDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		fmt.Printf("Error creating data directory: %v\n", err)
		return
	}

	configFilePath = filepath.Join(dataDir, "config.json")
}

// LoadConfig reads the configuration from the file system
func LoadConfig() (*Config, error) {
	cfg := &Config{}

	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		// Return default empty config if file doesn't exist
		return cfg, nil
	}

	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

// SaveConfig writes the configuration to the file system
func SaveConfig(cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configFilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
