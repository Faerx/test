package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"sos/internal/logger"

	"golang.org/x/term"
)

func ProcessFilePath(path string) (string, error) {

	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("to abs path ne smog %v", err)
	}

	fileInfo, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path '%s' netu", path)
		}
		return "", fmt.Errorf("fetching path %v ", path)
	}

	if !fileInfo.Mode().IsRegular() {
		return "", fmt.Errorf(" path '%s' ne file ", path)
	}

	return absPath, nil
}
func GetPass() ([]byte, error) {
	fmt.Println("pass:")

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("faild to set termina %w", err)
	}
	defer safeRestore(int(os.Stdin.Fd()), oldState)

	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("faild to read pass %w", err)
	}

	return pass, nil
}

func safeRestore(fd int, state *term.State) {
	if err := term.Restore(fd, state); err != nil {
		logger.HaltOnError(fmt.Errorf("fail restor term: %v", err), "Terminal kal")
	}
}
