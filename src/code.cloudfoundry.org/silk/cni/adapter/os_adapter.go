package adapter

import (
	"os"
)

type OsAdapter struct{}

func (*OsAdapter) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (*OsAdapter) IsNotExist(err error) bool {
	return os.IsNotExist(err)
}
