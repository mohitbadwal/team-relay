//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateFileACLRejectsAdditionalIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-token")
	file, err := platformOpenNewSecretFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOpenedSecret(path, file, []byte("tr_dev_test\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := platformValidatePrivateRegularFile(path, info); err != nil {
		t.Fatalf("new private file failed ACL validation: %v", err)
	}

	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: privateFileFullControl,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(current.User.Sid),
			},
		},
		{
			AccessPermissions: windows.GENERIC_READ,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(world),
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := platformValidatePrivateRegularFile(path, info); err == nil {
		t.Fatal("ACL validation accepted a file readable by another identity")
	}
	if _, err := readPrivateSetupFile(path); err == nil {
		t.Fatal("private setup reader accepted a file readable by another identity")
	}
	if _, err := loadEnrollmentAttempt(path); err == nil {
		t.Fatal("enrollment retry loader accepted a record readable by another identity")
	}
}

func TestWindowsWriteThroughRenamePublishesPrivateFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "config.yaml")
	if err := writeSecret(target, nil); err != nil {
		t.Fatal(err)
	}
	stage, err := stageSecret(directory, "config.yaml", []byte("version: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := platformRenameSetupFile(stage, target); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "version: 1\n" {
		t.Fatalf("published payload = %q", payload)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := platformValidatePrivateRegularFile(target, info); err != nil {
		t.Fatalf("published file lost its private ACL: %v", err)
	}
}
