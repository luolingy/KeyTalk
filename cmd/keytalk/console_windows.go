//go:build windows

package main

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// Windows API 访问。
//
// 直接用 syscall 而不引入 golang.org/x/sys/windows：
// 整段需求只有四个函数，为此新增一个依赖不划算。
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")

	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procGetConsoleWindow      = kernel32.NewProc("GetConsoleWindow")
	procShowWindow            = user32.NewProc("ShowWindow")
	procMessageBoxW           = user32.NewProc("MessageBoxW")
)

const (
	swHide      = 0
	mbIconError = 0x10
	mbTopmost   = 0x1000
)

// consoleHidden 记录本进程是否把自己的控制台藏了起来。
//
// reportFatal 依据它决定"能不能靠 stderr 说话"：
// 控制台藏起来之后，往 stderr 写等于什么也没说。
var consoleHidden = false

// argsRequestGUI 扫描命令行，判断是否显式要求图形界面。
//
// 需要在 main 里就能得出结论（早于 flag.Parse），
// 因为隐藏控制台必须发生在任何输出之前。
func argsRequestGUI() bool {
	for _, a := range os.Args[1:] {
		a = strings.TrimLeft(a, "-")
		if a == "gui" || strings.HasPrefix(a, "gui=") {
			return true
		}
	}
	return false
}

// ownsConsole 报告本进程是否**独占**当前控制台。
//
// 这是区分"双击启动"与"从终端启动"的关键：
//
//   - 双击时 Windows 为本进程新建一个控制台，
//     GetConsoleProcessList 只会返回本进程 → 1；
//   - 从终端启动时，同一个控制台上还挂着 pwsh.exe/cmd.exe，
//     因此返回 2 以上（终端本身也算一个）。
//
// 只有第一种情况才可以隐藏：第二种里那个窗口是**用户的终端**，
// 把它藏起来等于把用户的 shell 藏起来——比留着窗口糟糕得多。
func ownsConsole() bool {
	var pids [8]uint32
	n, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)),
	)
	return n == 1
}

// hideOwnConsole 在"双击启动"时隐藏那个多余的控制台窗口。
//
// 为什么不用 -H=windowsgui 一步解决：
// 那个链接选项会把 stdout 一并切断，同一个可执行文件就再也
// 无法当命令行工具用——而脚本、e2e.ps1、排错都依赖它。
// 自己隐藏窗口保住了两种用法，代价是双击时有一个很短的闪现。
// 需要完全不闪现的构建见 build.ps1 -GuiOnly。
//
// ⚠️ 必须在任何输出**之前**调用，否则用户会先看到一屏文字
// 再看到窗口消失。
func hideOwnConsole(bareLaunch bool) {
	if !bareLaunch && !argsRequestGUI() {
		return
	}
	if !ownsConsole() {
		return
	}
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return
	}
	procShowWindow.Call(hwnd, swHide)
	consoleHidden = true
}

// messageBox 弹一个系统对话框。
//
// 用途：图形模式启动失败时用户看不到任何东西（控制台是藏着的），
// 程序会"闪一下就没了"，用户只会以为它坏了。
// 这种情况下弹窗是唯一有效的告知方式。
func messageBox(title, text string) {
	t, err1 := syscall.UTF16PtrFromString(title)
	b, err2 := syscall.UTF16PtrFromString(text)
	if err1 != nil || err2 != nil {
		return
	}
	procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(b)),
		uintptr(unsafe.Pointer(t)),
		uintptr(mbIconError|mbTopmost),
	)
}
