package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testPass = "correct horse battery staple"

// newTestStore 建一个临时目录上的身份存储。
func newTestStore(t *testing.T) *IdentityStore {
	t.Helper()
	return NewIdentityStore(t.TempDir())
}

// TestCreateThenUnlockRoundTrip 是最基本的可用性断言：
// 建好的身份必须能用同一个口令解回来，且指纹不变。
func TestCreateThenUnlockRoundTrip(t *testing.T) {
	st := newTestStore(t)

	created, err := st.Create("alice", testPass)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	want := created.Fingerprint()

	unlocked, err := st.Unlock(testPass)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	defer unlocked.Close()

	if got := unlocked.Fingerprint(); got != want {
		t.Fatalf("fingerprint changed across a save/load cycle: %s -> %s\n"+
			"this is the worst possible failure: every contact that "+
			"exchanged public keys would stop handshaking", want, got)
	}
}

// TestPrivateKeyIsNotOnDiskInPlaintext 是本文件最重要的断言。
//
// 这个测试的存在理由就是整个 identity_store 的存在理由。
// 如果它会失败，说明口令加密只是个装饰。
func TestPrivateKeyIsNotOnDiskInPlaintext(t *testing.T) {
	st := newTestStore(t)

	prov, err := st.Create("alice", testPass)
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Close()

	raw, err := os.ReadFile(st.Path())
	if err != nil {
		t.Fatal(err)
	}

	// 1. 不能出现私钥的 armor 头。
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("identity.json contains a PRIVATE KEY armor header; " +
			"the private key is sitting on disk in the clear")
	}

	// 2. 结构上不能有非空的明文字段。
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if v, ok := doc["private_key"]; ok {
		if s, _ := v.(string); s != "" {
			t.Fatalf("the plaintext private_key field is present and holds %d "+
				"bytes; the legacy field must never be written again", len(s))
		}
	}
	if _, ok := doc["keystore"]; !ok {
		t.Error("no keystore block: the private key is not wrapped by a passphrase")
	}
	if _, ok := doc["sealed_private_key"]; !ok {
		t.Error("no sealed_private_key block")
	}

	// 3. 导出的私钥正文不能整段出现在文件里。
	armored, err := prov.ExportPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	body := armorBody(armored)
	if body != "" && bytes.Contains(raw, []byte(body)) {
		t.Fatal("the armored private key body appears verbatim in identity.json")
	}
}

// armorBody 取出 armored 文本的中间正文（去掉头尾与字段行）。
func armorBody(armored string) string {
	var b strings.Builder
	inBody := false
	for _, line := range strings.Split(armored, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "-----") {
			if inBody {
				break
			}
			inBody = true
			continue
		}
		if !inBody || strings.Contains(line, ":") {
			continue
		}
		b.WriteString(line)
	}
	return b.String()
}

// TestWrongPassphraseRejected 验证口令错误会被明确拒绝。
func TestWrongPassphraseRejected(t *testing.T) {
	st := newTestStore(t)
	prov, err := st.Create("alice", testPass)
	if err != nil {
		t.Fatal(err)
	}
	prov.Close()

	_, err = st.Unlock("wrong passphrase")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Unlock with a wrong passphrase returned %v, want ErrWrongPassphrase", err)
	}
}

// TestCreateRefusesEmptyPassphrase 验证不会悄悄退化成明文存储。
func TestCreateRefusesEmptyPassphrase(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.Create("alice", ""); err == nil {
		t.Fatal("Create accepted an empty passphrase; that would silently " +
			"produce an unprotected identity")
	}
	if _, err := os.Stat(st.Path()); !os.IsNotExist(err) {
		t.Error("a rejected Create still wrote an identity file")
	}
}

// TestTamperedSealedKeyDetected 验证改一个字节就会解密失败。
func TestTamperedSealedKeyDetected(t *testing.T) {
	st := newTestStore(t)
	prov, err := st.Create("alice", testPass)
	if err != nil {
		t.Fatal(err)
	}
	prov.Close()

	mutateIdentityFile(t, st, func(doc map[string]any) {
		sealed := doc["sealed_private_key"].(map[string]any)
		ct := sealed["ciphertext"].(string)
		sealed["ciphertext"] = flipBase64Char(ct)
	})

	if _, err := st.Unlock(testPass); err == nil {
		t.Fatal("a tampered sealed private key still decrypted")
	}
}

// TestTamperedFingerprintDetected 验证 AAD 绑定的指纹被改动后无法解锁。
func TestTamperedFingerprintDetected(t *testing.T) {
	st := newTestStore(t)
	prov, err := st.Create("alice", testPass)
	if err != nil {
		t.Fatal(err)
	}
	prov.Close()

	mutateIdentityFile(t, st, func(doc map[string]any) {
		// 同时改内外两份，否则会被一致性校验先拦下——
		// 这里要单独验证 AAD 绑定本身有效。
		ks := doc["keystore"].(map[string]any)
		other := strings.Repeat("AB", 20)
		ks["fp"] = other
		doc["fingerprint"] = other
	})

	if _, err := st.Unlock(testPass); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Unlock after tampering with the fingerprint returned %v, "+
			"want ErrWrongPassphrase (the AAD must bind the fingerprint)", err)
	}
}

// TestOuterFingerprintMismatchRejected 验证外层指纹被单独篡改会被发现。
//
// 攻击场景：只改外层那一个字段，让解锁界面显示成另一个身份，
// 而内层密钥完好、解锁本该成功。
func TestOuterFingerprintMismatchRejected(t *testing.T) {
	st := newTestStore(t)
	prov, err := st.Create("alice", testPass)
	if err != nil {
		t.Fatal(err)
	}
	prov.Close()

	mutateIdentityFile(t, st, func(doc map[string]any) {
		doc["fingerprint"] = strings.Repeat("CD", 20)
	})

	if _, err := st.LoadMeta(); !errors.Is(err, ErrKeystoreFormat) {
		t.Fatalf("LoadMeta with a mismatched outer fingerprint returned %v, "+
			"want ErrKeystoreFormat", err)
	}
}

// TestLegacyPlaintextIdentityStillLoads 验证 v1 身份仍可读取。
//
// 老用户升级后不能"掉身份"：读不了就会静默生成新密钥，
// 指纹改变，所有联系人握手失败。
func TestLegacyPlaintextIdentityStillLoads(t *testing.T) {
	dir := t.TempDir()
	st := NewIdentityStore(dir)

	// 先用 v1 明文格式造一份。
	prov, err := st.CreateUnencrypted("legacy")
	if err != nil {
		t.Fatal(err)
	}
	want := prov.Fingerprint()
	prov.Close()

	meta, err := st.LoadMeta()
	if err != nil {
		t.Fatal(err)
	}
	if meta.Encrypted {
		t.Error("a v1 identity was reported as encrypted")
	}
	if !meta.LegacyPlaintext {
		t.Error("a v1 identity was not flagged as legacy plaintext; " +
			"the UI must be able to warn the user")
	}

	// 明文身份无需口令即可取出。
	got, err := st.Unlock("")
	if err != nil {
		t.Fatalf("unlock of a legacy identity: %v", err)
	}
	defer got.Close()
	if got.Fingerprint() != want {
		t.Error("legacy fingerprint changed across load")
	}
}

// TestExportImportRoundTrip 验证备份与迁移路径。
func TestExportImportRoundTrip(t *testing.T) {
	src := newTestStore(t)
	prov, err := src.Create("alice", testPass)
	if err != nil {
		t.Fatal(err)
	}
	want := prov.Fingerprint()
	prov.Close()

	armored, err := src.ExportPrivateKey(testPass)
	if err != nil {
		t.Fatal(err)
	}

	// 导入到另一个目录，换一个新口令。
	dst := newTestStore(t)
	imported, err := dst.Import(armored, "a different passphrase", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := imported.Fingerprint(); got != want {
		t.Fatalf("imported fingerprint %s != original %s", got, want)
	}
	imported.Close()

	unlocked, err := dst.Unlock("a different passphrase")
	if err != nil {
		t.Fatalf("unlock of the imported identity: %v", err)
	}
	defer unlocked.Close()
	if got := unlocked.Fingerprint(); got != want {
		t.Error("imported identity unlocked to a different fingerprint")
	}

	// 旧口令必须在新目录里无效。
	if _, err := dst.Unlock(testPass); !errors.Is(err, ErrWrongPassphrase) {
		t.Error("the original passphrase still works after re-encryption")
	}
}

// TestExportPrivateKeyRequiresCorrectPassphrase 验证导出私钥需要再次确认口令。
//
// 解锁后的会话里不该有一个无条件可用的"导出私钥"按钮。
func TestExportPrivateKeyRequiresCorrectPassphrase(t *testing.T) {
	st := newTestStore(t)
	prov, err := st.Create("alice", testPass)
	if err != nil {
		t.Fatal(err)
	}
	prov.Close()

	if _, err := st.ExportPrivateKey("nope"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("ExportPrivateKey with a wrong passphrase returned %v, "+
			"want ErrWrongPassphrase", err)
	}
	if _, err := st.ExportPrivateKey(testPass); err != nil {
		t.Fatalf("ExportPrivateKey with the correct passphrase: %v", err)
	}
}

// TestLoadMetaOnMissingIdentity 验证没有身份时的报告方式。
func TestLoadMetaOnMissingIdentity(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.LoadMeta(); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("LoadMeta on an empty directory returned %v, want ErrNoIdentity", err)
	}
}

// TestPublicKeyFileIsWritten 验证公钥被单独落盘，便于直接发给对方。
func TestPublicKeyFileIsWritten(t *testing.T) {
	st := newTestStore(t)
	prov, err := st.Create("alice", testPass)
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Close()

	onDisk, err := os.ReadFile(st.PublicKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(onDisk, []byte("BEGIN PGP PUBLIC KEY BLOCK")) {
		t.Fatal("public.key does not look like an armored public key")
	}
	if got := string(onDisk); got != string(prov.PublicKey()) {
		t.Error("public.key does not match the identity's public key")
	}

	// 公钥文件是可分发的，权限不必是 0600；但身份文件必须是。
	//
	// ⚠️ 这条断言只在类 Unix 上有意义。Windows 没有 POSIX 权限位，
	// Go 的 Mode().Perm() 只能如实反映"只读"属性（可写即报 0666）。
	// 那里的保护来自用户配置目录的 ACL，不是 mode 位。
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(st.Path())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("identity.json permission = %o, want 600", perm)
	}
}

// TestParseFingerprintNormalisesGroupedInput 验证指纹输入的容错。
func TestParseFingerprintNormalisesGroupedInput(t *testing.T) {
	const canon = "ABCD1234EF567890ABCD1234EF567890ABCD1234"

	for _, in := range []string{
		canon,
		strings.ToLower(canon),
		"ABCD 1234 EF56 7890 ABCD 1234 EF56 7890 ABCD 1234",
		"  " + strings.ToLower("ABCD 1234 EF56 7890 ABCD 1234 EF56 7890 ABCD 1234") + "  ",
	} {
		got, err := ParseFingerprint(in)
		if err != nil {
			t.Errorf("ParseFingerprint(%q): %v", in, err)
			continue
		}
		if got.String() != canon {
			t.Errorf("ParseFingerprint(%q) = %q, want %q", in, got, canon)
		}
	}

	for _, bad := range []string{"", "   ", "not-hex", "ABCXYZ"} {
		if _, err := ParseFingerprint(bad); err == nil {
			t.Errorf("ParseFingerprint(%q) accepted invalid input", bad)
		}
	}
}

// --- 测试辅助 ---

// mutateIdentityFile 读改写 identity.json。
func mutateIdentityFile(t *testing.T, st *IdentityStore, fn func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(st.Path())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	fn(doc)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(st.Path(), out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// flipBase64Char 改动 base64 中的一个字符，模拟篡改。
func flipBase64Char(s string) string {
	if s == "" {
		return "A"
	}
	b := []byte(s)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

var _ = filepath.Join
