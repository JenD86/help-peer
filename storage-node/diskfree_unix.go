//go:build linux || darwin || freebsd || netbsd || openbsd

package main

import "syscall"

// diskFreeBytes reports the space available to unprivileged writers on the
// filesystem holding path.
func diskFreeBytes(path string) (int64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize), true
}
