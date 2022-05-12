package sshproxy

import (
	"encoding/base64"
	"io/ioutil"
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
		data, err := base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		ret = append(ret, data)
	}
	return ret, nil
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
		if strings.HasPrefix(f, "~") {
			home, err := os.UserHomeDir()
			if err == nil {
				f = filepath.Join(home, f[1:])
			}
		}
		data, err := ioutil.ReadFile(f)
		if err != nil {
			return nil, err
		}
		ret = append(ret, data)
	}
	return ret, nil
}
