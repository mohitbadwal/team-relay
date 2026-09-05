//go:build windows

package receiver

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsLocalStateLoadersRejectFilesReadableByAnotherIdentity(t *testing.T) {
	tests := []struct {
		name   string
		create func(string) error
		load   func(string) error
	}{
		{
			name: "control token",
			create: func(path string) error {
				_, err := LoadOrCreateControlToken(path)
				return err
			},
			load: func(path string) error {
				_, err := LoadOrCreateControlToken(path)
				return err
			},
		},
		{
			name: "pending store",
			create: func(path string) error {
				_, err := NewPendingStore(path)
				return err
			},
			load: func(path string) error {
				_, err := NewPendingStore(path)
				return err
			},
		},
		{
			name: "approval store",
			create: func(path string) error {
				_, err := NewApprovalStore(path)
				return err
			},
			load: func(path string) error {
				_, err := NewApprovalStore(path)
				return err
			},
		},
		{
			name: "session store",
			create: func(path string) error {
				_, err := NewFileSessionStore(path)
				return err
			},
			load: func(path string) error {
				_, err := NewFileSessionStore(path)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state", "local-state")
			if err := test.create(path); err != nil {
				t.Fatal(err)
			}
			if err := makeWindowsFileWorldReadable(path); err != nil {
				t.Fatal(err)
			}
			if err := test.load(path); err == nil {
				t.Fatal("loader accepted local state readable by another identity")
			}
		})
	}
}

func makeWindowsFileWorldReadable(path string) error {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: 0x001f01ff,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(current.User.Sid),
			},
		},
		{
			AccessPermissions: windows.GENERIC_READ,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(world),
			},
		},
	}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}
