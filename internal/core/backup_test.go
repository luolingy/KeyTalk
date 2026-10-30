package core

import (
	"path/filepath"
	"testing"

	"github.com/exeliang/keytalk/internal/crypto"
)

// TestSetupBackupRoundTrip 验证通过 Setup 导出的备份能恢复出同一个身份。
func TestSetupBackupRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	src := newTestSetup(t, srcDir)
	if err := src.CreateIdentity("alice", setupPass); err != nil {
		t.Fatal(err)
	}
	wantFP := src.Fingerprint().String()

	peer := testIdentity(t, "bob")
	if _, err := src.AddContact("bob", string(peer.PublicKey())); err != nil {
		t.Fatal(err)
	}

	bakPath := filepath.Join(t.TempDir(), "alice.ktbackup")
	const exportPass = "export passphrase here"
	if err := src.ExportBackup(bakPath, exportPass); err != nil {
		t.Fatalf("ExportBackup: %v", err)
	}

	// 全新目录，从备份恢复。
	dstDir := t.TempDir()
	dst := newTestSetup(t, dstDir)
	if dst.Stage() != StageNeedsIdentity {
		t.Fatalf("fresh dir stage = %d, want StageNeedsIdentity", dst.Stage())
	}

	env, err := dst.ImportBackupDecoded(bakPath, exportPass)
	if err != nil {
		t.Fatalf("ImportBackupDecoded: %v", err)
	}
	if env.Fingerprint != wantFP {
		t.Errorf("preview fingerprint = %s, want %s", env.Fingerprint, wantFP)
	}

	if err := dst.ImportBackup(bakPath, exportPass, false); err != nil {
		t.Fatalf("ImportBackup: %v", err)
	}

	// 恢复后应当停在"需要解锁"而不是直接就绪——这正是设计要点：
	// 备份只把身份文件搬过来，并不携带解密它的能力，登录口令
	// 仍然必须重新输入。
	if dst.Stage() != StageNeedsUnlock {
		t.Fatalf("after import the stage is %d, want StageNeedsUnlock", dst.Stage())
	}
	if got := dst.Meta().Fingerprint.String(); got != wantFP {
		t.Errorf("restored fingerprint = %s, want %s", got, wantFP)
	}

	// 用原来的身份口令解锁成功 = 私钥完整。
	if err := dst.Unlock(setupPass); err != nil {
		t.Fatalf("the restored identity does not unlock with the original passphrase: %v", err)
	}
	if !dst.Ready() {
		t.Fatal("after unlocking, the setup is not ready")
	}

	// 底层文件也确实能独立解锁。
	store := crypto.NewIdentityStore(dstDir)
	prov, err := store.Unlock(setupPass)
	if err != nil {
		t.Fatalf("the restored identity does not unlock directly: %v", err)
	}
	prov.Close()

	// 通讯录也恢复了。
	if got := len(dst.Contacts()); got != 1 {
		t.Errorf("restored %d contacts, want 1", got)
	}
}

// TestSetupBackupWrongPassphrase 验证导出口令错时不破坏目标目录。
func TestSetupBackupWrongPassphrase(t *testing.T) {
	srcDir := t.TempDir()
	src := newTestSetup(t, srcDir)
	if err := src.CreateIdentity("bob", setupPass); err != nil {
		t.Fatal(err)
	}
	bakPath := filepath.Join(t.TempDir(), "bob.ktbackup")
	if err := src.ExportBackup(bakPath, "the real export pass"); err != nil {
		t.Fatal(err)
	}

	dst := newTestSetup(t, t.TempDir())
	if err := dst.ImportBackup(bakPath, "a wrong export pass", false); err == nil {
		t.Fatal("ImportBackup succeeded with a wrong export passphrase")
	}
	// 目标目录仍应处于"需要身份"状态。
	if dst.Stage() != StageNeedsIdentity {
		t.Errorf("a failed import changed the stage to %d", dst.Stage())
	}
}
