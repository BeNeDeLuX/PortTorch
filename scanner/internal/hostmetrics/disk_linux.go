//go:build linux

package hostmetrics

import "syscall"

// statDisk returns the space available to an unprivileged process and the
// filesystem's size. Bavail rather than Bfree: the blocks reserved for
// root are not space the scanner's service user can write into.
func statDisk(path string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.Bsize)
	return st.Bavail * bsize, st.Blocks * bsize, nil
}
