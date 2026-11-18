//go:build !windows

package server

import "syscall"

// diskFree 返回 path 所在文件系统的可用字节数与总字节数。
func diskFree(path string) (free, total int64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	bsize := int64(st.Bsize)
	return int64(st.Bavail) * bsize, int64(st.Blocks) * bsize
}
