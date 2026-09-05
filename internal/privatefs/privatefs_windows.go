//go:build windows

package privatefs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const privateFullControl windows.ACCESS_MASK = 0x001f01ff

func platformCreatePrivateDirectory(path string) error {
	descriptor, err := currentUserOnlyDescriptor(true)
	if err != nil {
		return fmt.Errorf("build current-user-only directory ACL: %w", err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	if err := windows.CreateDirectory(name, attributes); err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	return nil
}

func platformValidatePrivateDirectory(path string, _ os.FileInfo) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read directory ACL: %w", err)
	}
	return validateCurrentUserOnlyDescriptor(descriptor, true, true, false)
}

func platformOpenNewPrivateFile(path string, _ fs.FileMode) (*os.File, error) {
	descriptor, err := currentUserOnlyDescriptor(false)
	if err != nil {
		return nil, fmt.Errorf("build current-user-only file ACL: %w", err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
		0,
		attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		_ = os.Remove(path)
		return nil, errors.New("create OS file handle")
	}
	if err := validatePrivateHandle(handle); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("verify current-user-only file ACL: %w", err)
	}
	return file, nil
}

func platformValidatePrivateRegularFile(path string, _ os.FileInfo) error {
	return validateCurrentUserOnlyRegularFile(path, true)
}

func platformValidateContainedRegularFile(path string, _ os.FileInfo) error {
	return validateCurrentUserOnlyRegularFile(path, false)
}

func validateCurrentUserOnlyRegularFile(path string, requireProtected bool) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read file ACL: %w", err)
	}
	return validateCurrentUserOnlyDescriptor(descriptor, false, requireProtected, !requireProtected)
}

func platformValidatePrivateFileHandle(file *os.File) error {
	return validatePrivateHandle(windows.Handle(file.Fd()))
}

func platformReplaceFile(oldPath, newPath string) error {
	oldName, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newName, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(oldName, newName, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: err}
	}
	return nil
}

func platformPublishNewFile(oldPath, newPath string) error {
	oldName, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newName, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(oldName, newName, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: err}
	}
	return nil
}

func platformSyncDirectory(_ string) error {
	// There is no supported Windows equivalent of POSIX fsync on a directory.
	// Private files use write-through handles and publication renames use
	// MOVEFILE_WRITE_THROUGH instead.
	return nil
}

func currentUserOnlyDescriptor(directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sid := user.User.Sid.String()
	if sid == "" {
		return nil, errors.New("current user SID is unavailable")
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	return windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;" + flags + ";FA;;;" + sid + ")")
}

func validatePrivateHandle(handle windows.Handle) error {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	return validateCurrentUserOnlyDescriptor(descriptor, false, true, false)
}

func validateCurrentUserOnlyDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, directory, requireProtected, allowTokenOwner bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current user SID: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return errors.New("owner is unavailable")
	}
	ownerAllowed := windows.EqualSid(owner, user.User.Sid)
	if !ownerAllowed && allowTokenOwner {
		ownerAllowed, err = currentTokenOwnerMatches(owner)
		if err != nil {
			return fmt.Errorf("read current token owner SID: %w", err)
		}
	}
	if !ownerAllowed {
		return errors.New("owner is not the current user")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read security descriptor control: %w", err)
	}
	if requireProtected && control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("DACL inherits permissions")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("path has no restrictive DACL")
	}
	if dacl.AceCount != 1 {
		return fmt.Errorf("DACL has %d entries; want exactly one", dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return fmt.Errorf("read DACL entry: %w", err)
	}
	if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		return errors.New("DACL is not one allow entry")
	}
	if directory {
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return errors.New("directory DACL entry is inherited")
		}
		want := uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
		if ace.Header.AceFlags&want != want {
			return errors.New("directory DACL does not protect child objects")
		}
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !windows.EqualSid(aceSID, user.User.Sid) {
		return errors.New("DACL grants access to another identity")
	}
	if ace.Mask&privateFullControl != privateFullControl {
		return errors.New("current user does not have full control")
	}
	return nil
}

// Windows assigns an ordinary new object's owner from TokenOwner, which can
// legitimately differ from TokenUser for an elevated process. Runtime-created
// result files use the ordinary creation APIs of third-party agent CLIs, so the
// contained-file validator accepts that exact token-selected owner while still
// requiring the protected parent and a single full-control ACE for TokenUser.
func currentTokenOwnerMatches(candidate *windows.SID) (bool, error) {
	if candidate == nil || !candidate.IsValid() {
		return false, errors.New("candidate owner SID is unavailable")
	}
	type tokenOwnerInfo struct {
		Owner *windows.SID
	}
	token := windows.GetCurrentProcessToken()
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	if err != nil && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return false, err
	}
	if size < uint32(unsafe.Sizeof(tokenOwnerInfo{})) {
		return false, errors.New("token owner payload is invalid")
	}
	payload := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &payload[0], uint32(len(payload)), &size); err != nil {
		return false, err
	}
	tokenOwner := (*tokenOwnerInfo)(unsafe.Pointer(&payload[0])).Owner
	if tokenOwner == nil || !tokenOwner.IsValid() {
		return false, errors.New("token owner SID is unavailable")
	}
	return windows.EqualSid(candidate, tokenOwner), nil
}
