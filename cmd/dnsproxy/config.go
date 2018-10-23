package main

import toml "github.com/pelletier/go-toml"

type config struct {
	Addr          string   `toml:"addr"`
	UpServers     []string `toml:"servers"`
	WithCache     bool     `toml:"with-cache"`
	CacheFile     string   `toml:"cache-file"`
	WorkerPoolMin int      `toml:"worker-pool-min"`
	WorkerPoolMax int      `toml:"worker-pool-max"`
}

func loadConfig(fp string) (*config, error) {
	tree, err := toml.LoadFile(fp)
	if err != nil {
		return nil, err
	}
	cfg := new(config)
	err = tree.Unmarshal(cfg)
	return cfg, err
}

func defaultConfig() ([]byte, error) {
	cfg := &config{
		Addr:          ":53",
		UpServers:     []string{"8.8.8.8"},
		WithCache:     true,
		CacheFile:     "cache.json",
		WorkerPoolMin: 10,
		WorkerPoolMax: 100,
	}
	return toml.Marshal(cfg)
}
