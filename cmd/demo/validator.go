package demo

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

func valCollection(input string) error {
	if !strings.HasPrefix(input, "did:collection:") {
		return errors.New("invalid input string")
	}
	return nil
}

func valCredential(input string) error {
	if !strings.HasPrefix(input, "did:credential:") {
		return errors.New("invalid input string")
	}
	return nil
}

func valPublicKey(input string) error {
	if !strings.HasPrefix(input, "did:public_key:") {
		return errors.New("invalid input string")
	}
	return nil
}

func valUInt(input string) error {
	if n, err := strconv.Atoi(input); err != nil {
		return errors.New("Invalid integer")
	} else if n < 0 {
		return errors.New("Value must be > 0")
	}
	return nil
}

func valAlias(arg string) error {
	for alias := range config.Peers {
		if alias == arg {
			return nil
		}
	}
	return errors.Errorf("Unknown alias, use 'config' to see available")
}

func valFile(arg string) error {
	filepath := convertToRelativePath(arg)
	if fileInfo, err := os.Stat(filepath); err == nil && !fileInfo.IsDir() {
		if strings.HasSuffix(strings.ToLower(filepath), ".json") {
			return nil
		}
	}
	return errors.New("incorrect input, expected a JSON Credential File Path")
}

func convertToRelativePath(filename string) string {
	// Assuming the current file is located in the root directory of the project
	// Modify this path as per your actual project structure
	currentDir := "./"

	// Construct the relative path
	relativePath := filepath.Join(currentDir, "data", filename)

	// Clean the path to remove any redundant separators
	relativePath = filepath.Clean(relativePath)

	return relativePath
}
