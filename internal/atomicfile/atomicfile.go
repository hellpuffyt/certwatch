// Package atomicfile writes files by writing a temporary file in the same
// directory and renaming it over the destination, so readers never see a
// partially written file and a failed write leaves the old file intact.
package atomicfile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Write creates path with the given permission bits, filled by fill. On any
// error the destination is left untouched and the temporary file removed.
func Write(path string, perm os.FileMode, fill func(io.Writer) error) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if err = fill(tmp); err != nil {
		return err
	}
	if err = tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
