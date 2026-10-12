//go:build !windows

package main

// consoleHidden 在非 Windows 平台恒为 false。
//
// Linux/macOS 下从文件管理器启动一个可执行文件不会附带
// 额外的控制台窗口，没有需要隐藏的东西。
var consoleHidden = false

// hideOwnConsole 在非 Windows 平台无事可做。
func hideOwnConsole(bareLaunch bool) {}

// messageBox 在非 Windows 平台是空实现。
//
// 这里不做平台专属弹窗：Linux 桌面环境的通知机制
// （notify-send / zenity / D-Bus）差异太大且不一定装了，
// 强行实现反而不可靠。这些平台上控制台不会被隐藏，
// reportFatal 走 stderr，用户能看到。
func messageBox(title, text string) {}
