package main

import (
	"os"
	"path/filepath"
)

// legacyDataDir 是早期版本写死的默认数据目录。
//
// 保留它不是出于兼容洁癖，而是因为**身份私钥就放在这里**。
// 一次升级把用户的身份"弄丢"，意味着他的指纹变了——
// 所有此前交换过公钥的联系人都会握手失败，
// 而用户完全不知道发生了什么。
const legacyDataDir = "./keytalk-data"

// resolveDataDir 决定身份与数据的存放位置。
//
// 三级规则，顺序不能换：
//
//  1. 用户显式给了 -id → 无条件用它；
//  2. 当前目录已存在 ./keytalk-data → 继续用它（保住旧身份）；
//  3. 否则用系统用户配置目录（Windows 上是 %AppData%\KeyTalk）。
//
// 第 3 条是"一键启动"能够成立的前提：双击运行时的工作目录
// 是 exe 所在位置，那里可能是 Program Files、只读介质，
// 或者需要管理员权限的目录。写进用户配置目录才能保证成功，
// 而且不会在桌面上堆出一个数据文件夹。
//
// 没有返回 error：这里不存在值得中止启动的失败。
// 最坏情况是退回当前目录——宁可把数据放在手边，
// 也不要让用户面对一个打不开的程序。
func resolveDataDir(explicit string) string {
	if explicit != "" {
		// 转成绝对路径。双击启动时工作目录不可预料，
		// 相对路径会让下一次启动找不到同一份身份。
		if abs, err := filepath.Abs(explicit); err == nil {
			return abs
		}
		return explicit
	}

	if st, err := os.Stat(legacyDataDir); err == nil && st.IsDir() {
		if abs, err := filepath.Abs(legacyDataDir); err == nil {
			return abs
		}
		return legacyDataDir
	}

	if base, err := os.UserConfigDir(); err == nil && base != "" {
		return filepath.Join(base, "KeyTalk")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".keytalk")
	}

	return legacyDataDir
}
