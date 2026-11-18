//go:build windows

package server

import (
	"syscall"
	"unsafe"
)

// kernel32 暴露 GetDiskFreeSpaceExW。标准库的 syscall 包没有导出它
// （只有 x/sys/windows 有），为一个调用引入新依赖不划算，这里直接按
// DLL 动态取过程地址。
var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeSpace = kernel32.NewProc("GetDiskFreeSpaceExW")
)

// diskFree 返回 path 所在卷的可用字节数与总字节数。
func diskFree(path string) (free, total int64) {
	root, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0
	}
	var freeToCaller, totalBytes, totalFree uint64
	ret, _, _ := procGetDiskFreeSpace.Call(
		uintptr(unsafe.Pointer(root)),
		uintptr(unsafe.Pointer(&freeToCaller)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if ret == 0 {
		return 0, 0
	}
	return int64(freeToCaller), int64(totalBytes)
}
