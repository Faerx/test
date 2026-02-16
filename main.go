package main

import (
	"sos/cmd"

	"errors"
	"sos/internal/logger"
)

func main() {
	rootCmd := cmd.RootCmd()

	if err := rootCmd.Execute(); err != nil {
		logger.HaltOnError(errors.New("cannot proceed, exiting now"), "Init faled!")
	}
}
