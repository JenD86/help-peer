//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package main

// diskFreeBytes isn't implemented on this platform; capacity limits still
// apply, but the node can't detect a disk filling up for other reasons.
func diskFreeBytes(path string) (int64, bool) {
	return 0, false
}
