package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	PathsToDelete []string `json:"paths_to_delete" `
}

func LoadConfig(pathToConfig string) (*Config, error) {
	contents, err := os.ReadFile(pathToConfig)
	if err != nil {
		return nil, fmt.Errorf("loading config: %s", err)
	}

	config := &Config{}
	err = json.Unmarshal(contents, config)
	if err != nil {
		return nil, fmt.Errorf("reading config: %s", err)
	}

	return config, nil
}
