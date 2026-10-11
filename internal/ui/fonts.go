package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/font/opentype"
)

// 中日韩字体的候选路径。
//
// ⚠️ 这是一个真实且关键的问题：Gio 内置的 Go 字体**不包含任何 CJK 字形**。
// 若不额外加载字体，界面上所有中文都会渲染成豆腐块（▯▯▯）或空白。
// 对于一款中文用户为主的聊天工具，这不是"显示不美观"，而是**不可用**。
//
// 因此这里按优先级探测系统中文字体。全部缺失时**不静默降级**——
// 见 cjkFallbackWarning：启动时会在 stderr 明确告警，
// 因为"中文显示不出来"如果只表现成满屏方块，用户不会想到是缺字体。
var cjkCandidates = []string{
	// Windows
	`C:\Windows\Fonts\msyh.ttc`,   // 微软雅黑
	`C:\Windows\Fonts\msyh.ttf`,   // 微软雅黑（旧版单文件）
	`C:\Windows\Fonts\msyhbd.ttc`, // 微软雅黑 Bold
	`C:\Windows\Fonts\simhei.ttf`, // 黑体
	`C:\Windows\Fonts\Deng.ttf`,   // 等线
	`C:\Windows\Fonts\simsun.ttc`, // 宋体
	`C:\Windows\Fonts\msjh.ttc`,   // 微软正黑（繁体）

	// macOS
	`/System/Library/Fonts/PingFang.ttc`,
	`/System/Library/Fonts/STHeiti Light.ttc`,
	`/Library/Fonts/Arial Unicode.ttf`,

	// Linux（常见发行版路径）
	`/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc`,
	`/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc`,
	`/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc`,
	`/usr/share/fonts/truetype/wqy/wqy-microhei.ttc`,
	`/usr/share/fonts/truetype/arphic/uming.ttc`,
}

var (
	fontOnce     sync.Once
	fontColl     []font.FontFace
	cjkFontPath  string
	fontLoadErrs []string
)

// loadFonts 构建字体集合：Go 字体（拉丁/符号） + 系统中文字体。
//
// 只做一次。字体解析涉及读取十几 MB 的文件，不能每帧做——
// 那会立刻把 immediate-mode 的帧率拖垮。
func loadFonts() ([]font.FontFace, string, []string) {
	fontOnce.Do(func() {
		coll := gofont.Collection()

		for _, path := range cjkCandidates {
			data, err := os.ReadFile(path)
			if err != nil {
				// 文件不存在是**正常**的：不同系统字体不同。
				// 只有**解析失败**才值得记录告警——那通常意味着
				// 字体格式不受支持，换一个候选即可，但用户应当知道。
				continue
			}
			faces, err := opentype.ParseCollection(data)
			if err != nil {
				fontLoadErrs = append(fontLoadErrs,
					fmt.Sprintf("%s: %v", filepath.Base(path), err))
				continue
			}
			added := 0
			for _, f := range faces {
				coll = append(coll, f)
				added++
			}
			if added > 0 {
				cjkFontPath = path
				break
			}
		}

		fontColl = coll
	})
	return fontColl, cjkFontPath, fontLoadErrs
}

// cjkFontStatus 返回一行人类可读的字体状态，供启动日志与"关于"页使用。
//
// 故意把这件事**显式呈现**：若中文字体没加载成功，
// 用户看到满屏方块时应当能立刻知道原因，而不是以为程序坏了。
func cjkFontStatus() string {
	_, path, errs := loadFonts()
	if path != "" {
		return "中文字体: " + filepath.Base(path)
	}
	msg := "中文字体: 未找到（中文可能显示为方块）"
	if len(errs) > 0 {
		msg += "；解析失败: " + strings.Join(errs, ", ")
	}
	return msg
}
