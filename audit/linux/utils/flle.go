package utils

import (
	"os"
	"path/filepath"
)

func FilePathWalkDir(root string) ([]string, error) {
	var files = make([]string, 0)
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// 排除文件夹或软连接
		if !(info.IsDir() || info.Mode()&os.ModeSymlink == os.ModeSymlink) {
			files = append(files, path)
		}
		return nil
	})
	return files, nil
}
