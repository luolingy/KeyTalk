package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/exeliang/keytalk/internal/crypto"
	"github.com/exeliang/keytalk/internal/transport/lan"
)

const setupPass = "a sufficiently long passphrase"

// testBuildApp 返回一个 BuildApp 回调，用真实 loopback 传输层组装 App。
//
// 用真传输层而不是假实现：本文件测的是"配置阶段能否交出可用的 App"，
// 而"可用"的定义就是 core.New 接受它——里面包含对
// TrustedFingerprints 覆盖度的检查。假传输会绕过这些检查。
func testBuildApp(t *testing.T) func(SetupSession) (*App, error) {
	t.Helper()
	return func(sess SetupSession) (*App, error) {
		tr := lan.New(lan.Config{
			Fingerprint: sess.Identity.Fingerprint().String(),
			DisplayName: "test",
			ListenPort:  0,
		})
		if err := tr.Start(context.Background()); err != nil {
			return nil, err
		}

		fps := make([]string, 0, len(sess.Contacts))
		for _, c := range sess.Contacts {
			fps = append(fps, c.Fingerprint)
		}

		app, err := New(Config{
			Identity:            sess.Identity,
			Importer:            &crypto.PGPImporter{},
			Transport:           tr,
			Contacts:            sess.Contacts,
			TrustedFingerprints: fps,
			Persist:             sess.Persist,
			Store:               sess.Store,
			Logf:                func(string, ...any) {},
		})
		if err != nil {
			_ = tr.Close()
			return nil, err
		}
		t.Cleanup(app.Shutdown)
		return app, nil
	}
}

func newTestSetup(t *testing.T, dir string) *Setup {
	t.Helper()
	s, err := NewSetup(SetupConfig{
		DataDir:  dir,
		BuildApp: testBuildApp(t),
		Logf:     func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewSetup: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// TestSetupOnEmptyDirNeedsIdentity 验证全新目录会被识别为"还没有身份"。
func TestSetupOnEmptyDirNeedsIdentity(t *testing.T) {
	s := newTestSetup(t, t.TempDir())

	if got := s.Stage(); got != StageNeedsIdentity {
		t.Fatalf("Stage = %v, want StageNeedsIdentity", got)
	}
	if s.Ready() {
		t.Error("Ready() is true without an identity")
	}
	if _, err := s.App(); !errors.Is(err, ErrSetupNotReady) {
		t.Fatalf("App() before an identity returned %v, want ErrSetupNotReady", err)
	}
}

// TestSetupCreateIdentityReachesReady 是主路径。
func TestSetupCreateIdentityReachesReady(t *testing.T) {
	dir := t.TempDir()
	s := newTestSetup(t, dir)

	if err := s.CreateIdentity("alice", setupPass); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	if !s.Ready() {
		t.Fatal("not ready after creating an identity")
	}

	wantFP := s.Fingerprint()
	if !wantFP.Valid() {
		t.Fatal("Fingerprint() is invalid right after creating an identity")
	}

	app, err := s.App()
	if err != nil {
		t.Fatalf("App: %v", err)
	}
	if app.Fingerprint() != wantFP {
		t.Fatalf("App fingerprint %s != setup fingerprint %s", app.Fingerprint(), wantFP)
	}

	// 身份文件必须落在数据目录里。
	if _, err := os.Stat(filepath.Join(dir, "identity.json")); err != nil {
		t.Errorf("identity.json was not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "public.key")); err != nil {
		t.Errorf("public.key was not written: %v", err)
	}
}

// TestSetupRefusesWeakOrEmptyName 验证输入校验。
func TestSetupRefusesWeakOrEmptyName(t *testing.T) {
	s := newTestSetup(t, t.TempDir())

	if err := s.CreateIdentity("   ", setupPass); err == nil {
		t.Error("CreateIdentity accepted a blank name")
	}
	if err := s.CreateIdentity("alice", "short"); err == nil {
		t.Error("CreateIdentity accepted a passphrase shorter than the minimum")
	}
	if s.Ready() {
		t.Error("a rejected CreateIdentity still left the setup ready")
	}
}

// TestSetupOnEncryptedDirNeedsUnlock 验证重启后要求解锁，而不是明文读回。
func TestSetupOnEncryptedDirNeedsUnlock(t *testing.T) {
	dir := t.TempDir()

	first := newTestSetup(t, dir)
	if err := first.CreateIdentity("alice", setupPass); err != nil {
		t.Fatal(err)
	}
	wantFP := first.Fingerprint()
	first.Close()

	second := newTestSetup(t, dir)
	if got := second.Stage(); got != StageNeedsUnlock {
		t.Fatalf("Stage after restart = %v, want StageNeedsUnlock\n"+
			"the private key must not be readable without the passphrase", got)
	}
	if second.Ready() {
		t.Fatal("setup reports ready before the passphrase was given")
	}

	// 错误口令必须被拒绝，且不能把状态推进。
	if err := second.Unlock("wrong passphrase here"); err == nil {
		t.Fatal("Unlock accepted a wrong passphrase")
	}
	if second.Ready() {
		t.Fatal("a failed Unlock advanced the stage to ready")
	}

	if err := second.Unlock(setupPass); err != nil {
		t.Fatalf("Unlock with the correct passphrase: %v", err)
	}
	app, err := second.App()
	if err != nil {
		t.Fatalf("App after unlock: %v", err)
	}
	if got := app.Fingerprint(); got != wantFP {
		t.Fatalf("fingerprint changed across restart: %s -> %s", wantFP, got)
	}
}

// TestSetupImportIdentityRestoresFingerprint 验证从备份迁移身份。
func TestSetupImportIdentityRestoresFingerprint(t *testing.T) {
	srcDir := t.TempDir()
	src := newTestSetup(t, srcDir)
	if err := src.CreateIdentity("alice", setupPass); err != nil {
		t.Fatal(err)
	}
	wantFP := src.Fingerprint()

	armored, err := src.ExportPrivateKey(setupPass)
	if err != nil {
		t.Fatal(err)
	}
	src.Close()

	// 恢复到一台"新机器"（新目录），换新口令。
	dst := newTestSetup(t, t.TempDir())
	if err := dst.ImportIdentity(armored, "another long passphrase", ""); err != nil {
		t.Fatalf("ImportIdentity: %v", err)
	}
	if !dst.Ready() {
		t.Fatal("not ready after importing an identity")
	}
	// 显示名应当从密钥里回读，而不是让用户重输。
	if dst.IdentityName() != "alice" {
		t.Errorf("IdentityName() = %q, want %q (derived from the key)",
			dst.IdentityName(), "alice")
	}

	app, err := dst.App()
	if err != nil {
		t.Fatal(err)
	}
	if app.Fingerprint() != wantFP {
		t.Fatalf("imported fingerprint %s != original %s", app.Fingerprint(), wantFP)
	}
}

// TestSetupLegacyPlaintextNeedsNoUnlock 验证 v1 身份仍能直接启动。
func TestSetupLegacyPlaintextNeedsNoUnlock(t *testing.T) {
	dir := t.TempDir()

	// 造一份 v1 明文身份。
	legacy := crypto.NewIdentityStore(dir)
	prov, err := legacy.CreateUnencrypted("legacy")
	if err != nil {
		t.Fatal(err)
	}
	wantFP := prov.Fingerprint()
	prov.Close()

	s := newTestSetup(t, dir)
	if got := s.Stage(); got != StageReady {
		t.Fatalf("Stage for a legacy plaintext identity = %v, want StageReady\n"+
			"an upgrade must not lock the owner out of their own identity", got)
	}

	app, err := s.App()
	if err != nil {
		t.Fatal(err)
	}
	if app.Fingerprint() != wantFP {
		t.Error("legacy identity loaded with a different fingerprint")
	}

	// 但界面必须能知道这是明文身份，以便警告用户。
	meta := s.Meta()
	if meta == nil || !meta.LegacyPlaintext {
		t.Error("the legacy plaintext identity was not flagged for warning")
	}
}

// TestSetupAddContactPersists 验证加联系人会立刻落盘。
func TestSetupAddContactPersists(t *testing.T) {
	dir := t.TempDir()
	s := newTestSetup(t, dir)
	if err := s.CreateIdentity("alice", setupPass); err != nil {
		t.Fatal(err)
	}

	peer := testIdentity(t, "bob")
	added, err := s.AddContact("bob", string(peer.PublicKey()))
	if err != nil {
		t.Fatalf("AddContact: %v", err)
	}
	if added.Fingerprint != peer.Fingerprint().String() {
		t.Fatalf("fingerprint mismatch: got %s want %s", added.Fingerprint, peer.Fingerprint())
	}

	// 落盘后必须能被重新读出来——"界面显示已添加、重启后消失"
	// 是这类功能最常见的失败，必须在测试里挡住。
	reloaded, err := LoadContactFile(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded) != 1 {
		t.Fatalf("contacts.json holds %d entries, want 1", len(reloaded))
	}
	if reloaded[0].Fingerprint != peer.Fingerprint().String() {
		t.Error("the persisted contact has a different fingerprint")
	}
	if reloaded[0].Name != "bob" {
		t.Errorf("persisted name = %q, want %q", reloaded[0].Name, "bob")
	}
}

// TestSetupAddContactRejectsDuplicate 验证同一把公钥不能加两次。
//
// 重复会让用户以为安全地加了两个人，其实只有一个身份。
func TestSetupAddContactRejectsDuplicate(t *testing.T) {
	s := newTestSetup(t, t.TempDir())
	if err := s.CreateIdentity("alice", setupPass); err != nil {
		t.Fatal(err)
	}

	peer := testIdentity(t, "bob")
	if _, err := s.AddContact("bob", string(peer.PublicKey())); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddContact("bob-again", string(peer.PublicKey())); err == nil {
		t.Fatal("AddContact accepted the same public key twice")
	}
	if got := len(s.Contacts()); got != 1 {
		t.Errorf("contact count = %d, want 1", got)
	}
}

// TestSetupAddContactRejectsInvalidKey 验证垃圾输入被拒绝而不是写进配置。
func TestSetupAddContactRejectsInvalidKey(t *testing.T) {
	dir := t.TempDir()
	s := newTestSetup(t, dir)
	if err := s.CreateIdentity("alice", setupPass); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{"", "   ", "hello world", "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnot base64\n-----END PGP PUBLIC KEY BLOCK-----"} {
		if _, err := s.AddContact("x", bad); err == nil {
			t.Errorf("AddContact(%q) succeeded; invalid keys must not reach contacts.json", bad)
		}
	}

	// 失败之后不能留下一个空的 contacts.json 或半条记录。
	cs, err := LoadContactFile(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 0 {
		t.Errorf("failed AddContact calls left %d entries behind", len(cs))
	}
}

// TestContactFileRoundTrip 验证联系人文件格式的读写一致。
func TestContactFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	peerA := testIdentity(t, "a")
	peerB := testIdentity(t, "b")

	in := []ContactConfig{
		{Name: "a", Fingerprint: peerA.Fingerprint().String(), PublicKey: peerA.PublicKey()},
		{Name: "b", Fingerprint: peerB.Fingerprint().String(), PublicKey: peerB.PublicKey()},
	}
	if err := SaveContactFile(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadContactFile(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("got %d contacts, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].Name != in[i].Name || out[i].Fingerprint != in[i].Fingerprint {
			t.Errorf("contact %d round-tripped as %+v, want %+v", i, out[i], in[i])
		}
	}
}

// TestLoadContactFileMissingIsEmpty 验证没有联系人文件时不是错误。
func TestLoadContactFileMissingIsEmpty(t *testing.T) {
	cs, err := LoadContactFile(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("LoadContactFile on an empty dir: %v", err)
	}
	if len(cs) != 0 {
		t.Errorf("got %d contacts, want 0", len(cs))
	}
}
