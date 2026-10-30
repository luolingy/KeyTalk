package backup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/exeliang/keytalk/internal/crypto"
)

// makeIdentity 在一个目录里造一个加密身份。
func makeIdentity(t *testing.T, dir, name, pass string) crypto.Fingerprint {
	t.Helper()
	store := crypto.NewIdentityStore(dir)
	prov, err := store.Create(name, pass)
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}
	fp := prov.Fingerprint()
	prov.Close()
	return fp
}

// TestExportImportRoundTrip 是本包最重要的一条：导出再导入，
// 拿回一个指纹相同、能解锁的身份。
func TestExportImportRoundTrip(t *testing.T) {
	src := t.TempDir()
	identityPass := "correct horse battery staple"
	wantFP := makeIdentity(t, src, "alice", identityPass)

	bakPath := filepath.Join(t.TempDir(), "alice.ktbackup")
	contacts := []Contact{
		{Fingerprint: "AAAA", Name: "Bob", PublicKey: "-----BEGIN PGP PUBLIC KEY BLOCK-----", Verified: true},
	}
	const exportPass = "my export passphrase"
	if err := Export(src, bakPath, contacts, exportPass); err != nil {
		t.Fatalf("Export: %v", err)
	}

	// 导入到一个全新的目录。
	dst := t.TempDir()
	if err := Import(bakPath, dst, exportPass, false); err != nil {
		t.Fatalf("Import: %v", err)
	}

	// 1. 身份指纹一致。
	meta, err := crypto.NewIdentityStore(dst).LoadMeta()
	if err != nil {
		t.Fatalf("LoadMeta after import: %v", err)
	}
	if meta.Fingerprint.String() != wantFP.String() {
		t.Errorf("restored fingerprint = %s, want %s", meta.Fingerprint.String(), wantFP.String())
	}
	if meta.Name != "alice" {
		t.Errorf("restored name = %q, want alice", meta.Name)
	}
	if !meta.Encrypted {
		t.Error("the restored identity is not encrypted")
	}

	// 2. 用**身份口令**能解开它（说明私钥完好）。
	store := crypto.NewIdentityStore(dst)
	prov, err := store.Unlock(identityPass)
	if err != nil {
		t.Fatalf("the restored identity does not unlock with the original passphrase: %v", err)
	}
	prov.Close()
}

// TestWrongPassphraseRejected 验证导出口令错时拒绝导入。
func TestWrongPassphraseRejected(t *testing.T) {
	src := t.TempDir()
	makeIdentity(t, src, "bob", "identity passphrase 1")

	bakPath := filepath.Join(t.TempDir(), "bob.ktbackup")
	if err := Export(src, bakPath, nil, "right export pass"); err != nil {
		t.Fatal(err)
	}

	dst := t.TempDir()
	err := Import(bakPath, dst, "wrong export pass", false)
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Import with a wrong passphrase returned %v, want ErrWrongPassphrase", err)
	}
	// 失败的导入不该留下身份文件。
	if _, err := os.Stat(filepath.Join(dst, "identity.json")); !os.IsNotExist(err) {
		t.Error("a failed import left an identity.json behind")
	}
}

// TestNoPlaintextInBackup 验证备份包里看不到明文身份材料。
func TestNoPlaintextInBackup(t *testing.T) {
	src := t.TempDir()
	makeIdentity(t, src, "carol", "identity passphrase 2")

	bakPath := filepath.Join(t.TempDir(), "carol.ktbackup")
	const exportPass = "another export passphrase"
	if err := Export(src, bakPath, []Contact{
		{Fingerprint: "BBBB", Name: "secret contact name", PublicKey: "KEYDATA"},
	}, exportPass); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"secret contact name", "KEYDATA", "carol"} {
		if containsBytes(raw, []byte(leak)) {
			t.Errorf("backup file leaks %q in plaintext", leak)
		}
	}
}

// TestImportRefusesOverwrite 验证默认不覆盖已有身份。
func TestImportRefusesOverwrite(t *testing.T) {
	src := t.TempDir()
	makeIdentity(t, src, "dave", "identity passphrase 3")
	bakPath := filepath.Join(t.TempDir(), "dave.ktbackup")
	const exportPass = "export pass 3"
	if err := Export(src, bakPath, nil, exportPass); err != nil {
		t.Fatal(err)
	}

	dst := t.TempDir()
	makeIdentity(t, dst, "existing", "existing identity pass")

	err := Import(bakPath, dst, exportPass, false)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("Import over an existing identity returned %v, want ErrExists", err)
	}

	// 显式允许覆盖时才成功。
	if err := Import(bakPath, dst, exportPass, true); err != nil {
		t.Fatalf("Import with overwrite=true: %v", err)
	}
	if meta, err := crypto.NewIdentityStore(dst).LoadMeta(); err != nil || meta.Name != "dave" {
		t.Errorf("overwrite did not replace the identity: name=%v err=%v", meta.Name, err)
	}
}

// TestExportRefusesOverwrite 验证导出不会静默覆盖已有备份文件。
func TestExportRefusesOverwrite(t *testing.T) {
	src := t.TempDir()
	makeIdentity(t, src, "erin", "identity passphrase 4")
	bakPath := filepath.Join(t.TempDir(), "erin.ktbackup")

	if err := Export(src, bakPath, nil, "export passphrase"); err != nil {
		t.Fatal(err)
	}
	// 第二次导出到同一路径必须失败，而不是覆盖掉刚做好的备份。
	if err := Export(src, bakPath, nil, "export passphrase"); err == nil {
		t.Fatal("Export silently overwrote an existing backup file")
	}
}

// TestNotABackupRejected 验证乱七八糟的文件被拒绝。
func TestNotABackupRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "junk.ktbackup")
	if err := os.WriteFile(p, []byte("this is not a backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Import(p, t.TempDir(), "x", false); !errors.Is(err, ErrNotABackup) {
		t.Fatalf("Import of junk returned %v, want ErrNotABackup", err)
	}
}

// TestDecodeEnvelope 验证可以先解密看内容再决定是否导入。
func TestDecodeEnvelope(t *testing.T) {
	src := t.TempDir()
	fp := makeIdentity(t, src, "frank", "identity passphrase 5")
	bakPath := filepath.Join(t.TempDir(), "frank.ktbackup")
	const exportPass = "export pass 5"
	if err := Export(src, bakPath, []Contact{
		{Fingerprint: "CCCC", Name: "Grace", PublicKey: "K", Verified: true},
	}, exportPass); err != nil {
		t.Fatal(err)
	}

	env, err := DecodeEnvelope(bakPath, exportPass)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if env.Fingerprint != fp.String() {
		t.Errorf("envelope fingerprint = %s, want %s", env.Fingerprint, fp.String())
	}
	if env.Name != "frank" {
		t.Errorf("envelope name = %q, want frank", env.Name)
	}
	if len(env.Contacts) != 1 || env.Contacts[0].Name != "Grace" {
		t.Errorf("envelope contacts wrong: %+v", env.Contacts)
	}

	if _, err := DecodeEnvelope(bakPath, "wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("DecodeEnvelope with a wrong passphrase returned %v", err)
	}
}

// TestShortExportPassphraseRejected 验证太短的导出口令被拒绝。
func TestShortExportPassphraseRejected(t *testing.T) {
	src := t.TempDir()
	makeIdentity(t, src, "henry", "identity passphrase 6")
	p := filepath.Join(t.TempDir(), "h.ktbackup")
	if err := Export(src, p, nil, "short"); err == nil {
		t.Fatal("Export accepted a 5-character export passphrase")
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
