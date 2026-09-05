package protocol

import (
	"errors"
	"io/fs"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidatePortableFilename accepts a single filename that has the same safe
// meaning on Unix and Windows. Applying the Windows rules everywhere prevents
// a name accepted by one relay client from becoming a path, alternate data
// stream, or device when another teammate saves it on Windows.
func ValidatePortableFilename(name string) error {
	if name == "" || name != strings.TrimSpace(name) || name == "." || name == ".." {
		return errors.New("filename must be a non-empty direct-child name without surrounding whitespace")
	}
	if !utf8.ValidString(name) || len([]byte(name)) > 255 {
		return errors.New("filename must be valid UTF-8 and at most 255 bytes")
	}
	if strings.ContainsAny(name, `<>:"/\|?*`) {
		return errors.New("filename contains a path separator or Windows-reserved character")
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return errors.New("filename cannot end in a dot or space")
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return errors.New("filename contains a control character")
		}
	}

	stem := name
	if index := strings.IndexByte(stem, '.'); index >= 0 {
		stem = stem[:index]
	}
	switch strings.ToUpper(stem) {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"COM¹", "COM²", "COM³",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
		"LPT¹", "LPT²", "LPT³":
		return errors.New("filename is a Windows-reserved device name")
	}
	return nil
}

// ValidatePortableRelativePath accepts slash-separated, traversal-free paths
// whose individual components are valid on both Unix and Windows.
func ValidatePortableRelativePath(value string) error {
	if value == "" || value != strings.TrimSpace(value) || value == "." || !fs.ValidPath(value) {
		return errors.New("path must be a slash-separated relative path without traversal")
	}
	for _, component := range strings.Split(value, "/") {
		if err := ValidatePortableFilename(component); err != nil {
			return err
		}
	}
	return nil
}
