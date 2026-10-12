//go:build windows

package main

import (
	"os"
	"testing"
)

// TestArgsRequestGUI 验证命令行扫描能找到图形界面请求。
//
// 这段逻辑决定"要不要隐藏控制台窗口"。扫漏了会留下一个多余窗口，
// 扫错了更糟：从终端启动时也去隐藏，等于把用户的 shell 藏起来。
func TestArgsRequestGUI(t *testing.T) {
	prev := os.Args
	t.Cleanup(func() { os.Args = prev })

	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"keytalk"}, false},
		{[]string{"keytalk", "-gui"}, true},
		{[]string{"keytalk", "--gui"}, true},
		{[]string{"keytalk", "-gui=true"}, true},
		{[]string{"keytalk", "-id", "x", "-gui"}, true},
		{[]string{"keytalk", "-id", "x"}, false},
		{[]string{"keytalk", "-setup", "-name", "alice"}, false},
		{[]string{"keytalk", "-name", "guidance"}, false}, // 不能误匹配
	}

	for _, c := range cases {
		os.Args = c.args
		if got := argsRequestGUI(); got != c.want {
			t.Errorf("argsRequestGUI(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

// TestConsoleNotHiddenWithoutGUIIntent 验证没有任何图形界面意图时
// 绝不会隐藏控制台。
//
// 这是一条安全断言：本测试从终端运行，若 ownsConsole 判断错了，
// 隐藏掉的是**用户的终端窗口**。因此这里要求
// hideOwnConsole 在裸启动以外的场景下保持 consoleHidden 不变。
func TestConsoleNotHiddenWithoutGUIIntent(t *testing.T) {
	prev := os.Args
	t.Cleanup(func() { os.Args = prev })

	os.Args = []string{"keytalk", "-setup", "-name", "alice"}
	consoleHidden = false

	hideOwnConsole(false)

	if consoleHidden {
		t.Fatal("hideOwnConsole hid the console for a CLI-only invocation; " +
			"if this ran from a terminal it would have hidden the user's shell")
	}
}
