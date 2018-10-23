package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	dnsproxy "github.com/Asphaltt/dnsproxy-go"
)

var (
	flgConfig = flag.String("c", "config.toml", "toml config file path for dnsproxy")

	flgPrintDefaultConfig = flag.Bool("pdc", false, "print default config with toml format")
)

func main() {
	flag.Parse()

	if *flgPrintDefaultConfig {
		data, _ := defaultConfig()
		fmt.Println(string(data))
		return
	}

	cfg, err := loadConfig(*flgConfig)
	if err != nil {
		fmt.Printf("failed to load config from %s, err: %v\n", *flgConfig, err)
		return
	}

	serverCfg := &dnsproxy.Config{
		Addr:          cfg.Addr,
		UpServers:     cfg.UpServers,
		WithCache:     cfg.WithCache,
		CacheFile:     cfg.CacheFile,
		WorkerPoolMin: cfg.WorkerPoolMin,
		WorkerPoolMax: cfg.WorkerPoolMax,
	}

	if err := dnsproxy.Start(serverCfg); err != nil {
		fmt.Printf("failed to start dnsproxy, err: %v\n", err)
		return
	}
	defer dnsproxy.Close()

	fmt.Println("dnsproxy listens on", cfg.Addr)

	fmt.Printf("Quit -> %v\n", <-quitSignal())
}

func quitSignal() <-chan os.Signal {
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGKILL)
	return signals
}
