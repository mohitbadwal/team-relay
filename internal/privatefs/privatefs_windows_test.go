//go:build windows

package privatefs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateDirectoryACLIsProtectedAndInherited(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureDirectory(directory); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDirectory(directory); err != nil {
		t.Fatalf("private directory validation failed: %v", err)
	}

	child := filepath.Join(directory, "runtime-output.txt")
	if err := os.WriteFile(child, []byte("private by inheritance"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := ValidateContainedRegularFile(child); err != nil {
		t.Fatalf("ordinary child did not inherit a current-user-only ACL: %v", err)
	}
	if err := ValidateRegularFile(child); err == nil {
		t.Fatal("ordinary inherited child was accepted as strict durable state")
	}
}

func TestWindowsValidationRejectsAdditionalIdentityAndEnsureDoesNotRewriteDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureDirectory(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "token")
	if err := WriteNewFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
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
		allowACE(current.User.Sid, privateFullControl, windows.TRUSTEE_IS_USER, windows.NO_INHERITANCE),
		allowACE(world, windows.GENERIC_READ, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.NO_INHERITANCE),
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
	if _, err := ReadFile(path); err == nil {
		t.Fatal("private reader accepted a file readable by another identity")
	}

	directoryACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		allowACE(current.User.Sid, privateFullControl, windows.TRUSTEE_IS_USER, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		allowACE(world, windows.GENERIC_READ, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		directory,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		directoryACL,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDirectory(directory); err == nil {
		t.Fatal("directory validator accepted an ACL for another identity")
	}
	if err := EnsureDirectory(directory); err == nil {
		t.Fatal("EnsureDirectory silently rewrote a caller-owned permissive directory")
	}
}

func allowACE(sid *windows.SID, permissions windows.ACCESS_MASK, trusteeType windows.TRUSTEE_TYPE, inheritance uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: permissions,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
