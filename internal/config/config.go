package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	NodeID          string   `yaml:"node_id"`
	Region          string   `yaml:"region"`
	Iface           string   `yaml:"iface"`
	StaticBlocklist []string `yaml:"static_blocklist"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Iface == "" {
		return nil, fmt.Errorf("iface is required")
	}
	if c.NodeID == "" {
		h, _ := os.Hostname()
		c.NodeID = h
	}
	return &c, nil
}
