package fswalk

import (
	"io/fs"
	"path/filepath"
	"strings"
)

func WalkMarkdown(root string, fn func(path string) error) error {
	return WalkByExt(root, ".md", fn)
}

func WalkByExt(root string, ext string, fn func(path string) error) error {
	ext = strings.ToLower(ext)
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ext) {
			return fn(path)
		}
		return nil
	})
}
