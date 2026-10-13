//go:build !linux

package hostmetrics

import "errors"

func statDisk(string) (uint64, uint64, error) {
	return 0, 0, errors.New("disk usage is only read on Linux")
}
