package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// inTempDir 把测试的工作目录切到一个临时目录，结束后还原。
//
// resolveDataDir 的"旧目录优先"规则是相对当前目录判断的，
// 因此必须在可控的目录里测。
func inTempDir(t *testing.T) string {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	return dir
}

// TestResolveDataDirHonoursExplicit 验证显式 -id 永远优先于一切默认。
func TestResolveDataDirHonoursExplicit(t *testing.T) {
	inTempDir(t)
	// 即便存在旧目录，显式指定也必须赢。
	if err := os.Mkdir("keytalk-data", 0o700); err != nil {
		t.Fatal(err)
	}

	got := resolveDataDir("./explicit")
	want := filepath.Join(mustAbs(t, "."), "explicit")
	if got != want {
		t.Errorf("resolveDataDir(%q) = %q, want %q", "./explicit", got, want)
	}
}

// TestResolveDataDirReturnsAbsolutePath 验证结果总是绝对路径。
//
// 这条规则服务于"双击启动"：双击时工作目录是 exe 所在位置，
// 返回相对路径会让**下一次**启动去别处找身份，
// 表现为"我的指纹怎么变了"——而用户很难联想到原因。
func TestResolveDataDirReturnsAbsolutePath(t *testing.T) {
	inTempDir(t)

	for _, explicit := range []string{"", "./rel", "sub/dir"} {
		got := resolveDataDir(explicit)
		if !filepath.IsAbs(got) {
			t.Errorf("resolveDataDir(%q) = %q, want an absolute path", explicit, got)
		}
		if got == "" {
			t.Errorf("resolveDataDir(%q) returned an empty path", explicit)
		}
	}
}

// TestResolveDataDirPrefersExistingLegacyDir 是本文件最重要的一条断言。
//
// 旧版本把数据写在 ./keytalk-data。如果新的默认值（用户配置目录）
// 无条件生效，老用户升级后程序会看不到自己的 identity.json，
// 于是**静默生成一把新密钥**——指纹变了，所有交换过公钥的
// 联系人都握手失败，而用户完全不知道发生了什么。
//
// 因此：已存在的旧目录必须赢过新默认值。
func TestResolveDataDirPrefersExistingLegacyDir(t *testing.T) {
	dir := inTempDir(t)
	legacy := filepath.Join(dir, "keytalk-data")
	if err := os.Mkdir(legacy, 0o700); err != nil {
		t.Fatal(err)
	}

	got := resolveDataDir("")
	if got != legacy {
		t.Fatalf("resolveDataDir() = %q, want %q\n"+
			"an existing legacy data directory must win over the new default; "+
			"otherwise an upgrade silently changes the user's fingerprint",
			got, legacy)
	}
}

// TestResolveDataDirUsesUserConfigDirWhenFresh 验证全新安装时
// 落到用户配置目录，而不是 exe 旁边。
//
// 理由：双击运行时工作目录可能是 Program Files 或只读介质，
// 在那里写数据会直接失败。
func TestResolveDataDirUsesUserConfigDirWhenFresh(t *testing.T) {
	inTempDir(t)

	got := resolveDataDir("")

	if strings.Contains(filepath.Base(got), "keytalk-data") {
		t.Errorf("resolveDataDir() = %q on a fresh install; "+
			"it must not fall back to the working directory, which may be "+
			"read-only when the binary is double-clicked", got)
	}

	base, err := os.UserConfigDir()
	if err == nil && base != "" {
		if !strings.HasPrefix(got, base) {
			t.Errorf("resolveDataDir() = %q, want a path under the user "+
				"config dir %q", got, base)
		}
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}
