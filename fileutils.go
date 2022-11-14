package common

import (
	"os"
)

func fileExists(filename string) (bool, error) {
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return !info.IsDir(), nil
}

func fileDelete(filename string) error {
	if err := os.Remove(filename); err != nil {
		return err
	}
	return nil
}
