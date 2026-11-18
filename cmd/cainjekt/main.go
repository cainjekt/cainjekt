package main

import (
	"log/slog"
	"os"
	"strings"

	"github.com/cainjekt/cainjekt/internal/app"
	"github.com/cainjekt/cainjekt/internal/config"
)

// logLevel parses CAINJEKT_LOG_LEVEL (debug, info, warn, error; default info).
func logLevel() slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(strings.TrimSpace(os.Getenv(config.EnvLogLevel)))); err != nil {
		return slog.LevelInfo
	}
	return l
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()}))
	if err := app.Run(log, os.Args[1:]); err != nil {
		log.Error("cainjekt failed", "error", err)
		os.Exit(1)
	}
}
