package sshproxy

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
)

func getQuery(datas []string, files []string) ([][]byte, error) {
	d, err := openDatas(datas)
	if err != nil {
		return nil, err
	}
	f, err := openFiles(files)
	if err != nil {
		return nil, err
	}

	ret := append(d, f...)
	return ret, nil
}

func openDatas(datas []string) ([][]byte, error) {
	if len(datas) == 0 {
		return [][]byte{}, nil
	}
	var ret [][]byte
	for _, s := range datas {
		if s == "" {
			continue
		}
		data, err := decodeBase64(s)
		if err != nil {
			return nil, err
		}
		ret = append(ret, data)
	}
	return ret, nil
}

// decodeBase64 decodes base64 in the URL-safe or the standard alphabet, with
// or without padding. A '+' of the standard alphabet arrives as a space when
// it was written unescaped in a query string, and is read as such.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("-", "+", "_", "/", " ", "+").Replace(s)
	return base64.RawStdEncoding.DecodeString(s)
}

func openFiles(files []string) ([][]byte, error) {
	if len(files) == 0 {
		return [][]byte{}, nil
	}
	var ret [][]byte
	for _, f := range files {
		if f == "" {
			continue
		}
		// Only expand "~" and "~/...", not "~user/..." which refers to another user's home.
		if f == "~" || strings.HasPrefix(f, "~/") {
			home, err := os.UserHomeDir()
			if err == nil {
				f = filepath.Join(home, f[1:])
			}
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		ret = append(ret, data)
	}
	return ret, nil
}
