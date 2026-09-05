//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsConfigAndDeviceTokenRejectFilesReadableByAnotherIdentity(t *testing.T) {
	t.Setenv("TEAM_RELAY_DEVICE_TOKEN", "")
	directory := filepath.Join(t.TempDir(), "state")
	configPath := filepath.Join(directory, "config.yaml")
	tokenPath := filepath.Join(directory, "device-token")
	writePrivateTestFile(t, configPath, []byte("version: 1\nrelay:\n  url: https://relay.example\n"))
	writePrivateTestFile(t, tokenPath, []byte("tr_dev_test\n"))

	if err := makeConfigFileWorldReadable(configPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil {
		t.Fatal("config loader accepted a config readable by another identity")
	}
	writePrivateTestFileAfterRemove(t, configPath, []byte("version: 1\nrelay:\n  url: https://relay.example\n"))
	if err := makeConfigFileWorldReadable(tokenPath); err != nil {
		t.Fatal(err)
	}
	config := Config{Relay: RelayConfig{TokenFile: tokenPath}}
	if _, err := config.DeviceToken(); err == nil {
		t.Fatal("device-token loader accepted a credential readable by another identity")
	}
}

func writePrivateTestFileAfterRemove(t *testing.T, path string, payload []byte) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writePrivateTestFile(t, path, payload)
}

func makeConfigFileWorldReadable(path string) error {
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
