// Package artifact creates recipient-local, per-request sandboxes for inbound
// attachments and outbound deliverables. Relay bytes remain untrusted until
// their descriptor, decoded size, and digest have all been verified locally.
package artifact

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/protocol"
	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

const requestDirectoryPrefix = "request-"

// Fetcher is intentionally identical to the authenticated relay client's
// artifact method without coupling this package to its concrete type.
type Fetcher interface {
	FetchArtifact(context.Context, string) (*protocol.ArtifactContent, error)
}

// Sandbox is an owned request directory. The opaque directory name is kept
// private so cleanup cannot be redirected to an arbitrary caller path.
type Sandbox struct {
	Root            string
	Attachments     []string
	ReturnDirectory string
	name            string
	returnInfo      os.FileInfo
}

type Manager struct {
	basePath string
	root     *os.Root
}

func NewManager(basePath string) (*Manager, error) {
	if strings.TrimSpace(basePath) == "" {
		return nil, errors.New("artifact runtime directory is required")
	}
	absolute, err := filepath.Abs(basePath)
	if err != nil {
		return nil, fmt.Errorf("resolve artifact runtime directory: %w", err)
	}
	if err := privatefs.EnsureDirectory(absolute); err != nil {
		return nil, fmt.Errorf("create artifact runtime directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("resolve artifact runtime directory links: %w", err)
	}
	if err := privatefs.ValidateDirectory(resolved); err != nil {
		return nil, fmt.Errorf("validate artifact runtime directory privacy: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return nil, errors.New("artifact runtime path is not a directory")
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		return nil, fmt.Errorf("open artifact runtime directory: %w", err)
	}
	return &Manager{basePath: filepath.Clean(resolved), root: root}, nil
}

func (m *Manager) Close() error {
	if m == nil || m.root == nil {
		return nil
	}
	return m.root.Close()
}

// Materialize downloads approved attachments into a newly created private
// directory. It must only be called after the local Allow Once decision.
func (m *Manager) Materialize(ctx context.Context, descriptors []protocol.ArtifactDescriptor, fetcher Fetcher) (*Sandbox, error) {
	if m == nil || m.root == nil {
		return nil, errors.New("artifact manager is unavailable")
	}
	if len(descriptors) > protocol.MaxAttachments {
		return nil, fmt.Errorf("request has %d attachments; maximum is %d", len(descriptors), protocol.MaxAttachments)
	}
	if len(descriptors) > 0 && fetcher == nil {
		return nil, errors.New("artifact fetcher is required")
	}
	if err := validateDescriptors(descriptors); err != nil {
		return nil, err
	}

	name, err := m.createRequestDirectory()
	if err != nil {
		return nil, err
	}
	sandbox := &Sandbox{
		name:            name,
		Root:            filepath.Join(m.basePath, name),
		ReturnDirectory: filepath.Join(m.basePath, name, "return-files"),
	}
	failed := true
	defer func() {
		if failed {
			_ = m.Cleanup(sandbox)
		}
	}()
	if err := privatefs.CreateDirectory(filepath.Join(sandbox.Root, "attachments")); err != nil {
		return nil, fmt.Errorf("create attachment directory: %w", err)
	}
	if err := privatefs.CreateDirectory(sandbox.ReturnDirectory); err != nil {
		return nil, fmt.Errorf("create return directory: %w", err)
	}
	returnInfo, err := m.root.Lstat(filepath.Join(name, "return-files"))
	if err != nil {
		return nil, fmt.Errorf("pin return directory identity: %w", err)
	}
	if returnInfo.Mode()&os.ModeSymlink != 0 || !returnInfo.IsDir() {
		return nil, errors.New("new return directory is not a regular directory")
	}
	sandbox.returnInfo = returnInfo

	seen := make(map[string]struct{}, len(descriptors))
	for _, descriptor := range descriptors {
		key := strings.ToLower(descriptor.Name)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate attachment filename %q", descriptor.Name)
		}
		seen[key] = struct{}{}
		content, err := fetcher.FetchArtifact(ctx, descriptor.ArtifactID)
		if err != nil {
			return nil, fmt.Errorf("fetch attachment %q: %w", descriptor.Name, err)
		}
		payload, err := verifyContent(descriptor, content)
		if err != nil {
			return nil, fmt.Errorf("verify attachment %q: %w", descriptor.Name, err)
		}
		absolute := filepath.Join(sandbox.Root, "attachments", descriptor.Name)
		file, err := privatefs.OpenNewFile(absolute, 0o400)
		if err != nil {
			return nil, fmt.Errorf("create attachment %q: %w", descriptor.Name, err)
		}
		if _, err := file.Write(payload); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("write attachment %q: %w", descriptor.Name, err)
		}
		if goruntime.GOOS != "windows" {
			if err := file.Chmod(0o400); err != nil {
				_ = file.Close()
				return nil, fmt.Errorf("make attachment %q read-only: %w", descriptor.Name, err)
			}
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("sync attachment %q: %w", descriptor.Name, err)
		}
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("close attachment %q: %w", descriptor.Name, err)
		}
		if err := privatefs.ValidateRegularFile(absolute); err != nil {
			return nil, fmt.Errorf("validate attachment %q privacy: %w", descriptor.Name, err)
		}
		sandbox.Attachments = append(sandbox.Attachments, filepath.Join(sandbox.Root, "attachments", descriptor.Name))
	}
	if err := privatefs.SyncDirectory(filepath.Join(sandbox.Root, "attachments")); err != nil {
		return nil, fmt.Errorf("sync attachment directory: %w", err)
	}
	attachmentDirectory, err := m.root.Open(filepath.Join(name, "attachments"))
	if err != nil {
		return nil, fmt.Errorf("open attachment directory: %w", err)
	}
	if goruntime.GOOS != "windows" {
		if err := attachmentDirectory.Chmod(0o500); err != nil {
			_ = attachmentDirectory.Close()
			return nil, fmt.Errorf("make attachment directory read-only: %w", err)
		}
		if err := attachmentDirectory.Sync(); err != nil {
			_ = attachmentDirectory.Close()
			return nil, fmt.Errorf("sync attachment directory protections: %w", err)
		}
	}
	if err := attachmentDirectory.Close(); err != nil {
		return nil, fmt.Errorf("close attachment directory: %w", err)
	}
	failed = false
	return sandbox, nil
}

// CollectResults accepts only bounded, regular, direct-child deliverables.
// Directories, links, archives, and executable files are rejected rather than
// being silently skipped so the recipient can see exactly why delivery failed.
func (m *Manager) CollectResults(sandbox *Sandbox) ([]protocol.AttachmentInput, error) {
	if err := m.validateSandbox(sandbox); err != nil {
		return nil, err
	}
	returnRoot, err := m.openOwnedReturnRoot(sandbox)
	if err != nil {
		return nil, fmt.Errorf("open return directory: %w", err)
	}
	defer returnRoot.Close()
	entries, err := fs.ReadDir(returnRoot.FS(), ".")
	if err != nil {
		return nil, fmt.Errorf("read return directory: %w", err)
	}
	if len(entries) > protocol.MaxAttachments {
		return nil, fmt.Errorf("runtime returned %d files; maximum is %d", len(entries), protocol.MaxAttachments)
	}

	results := make([]protocol.AttachmentInput, 0, len(entries))
	var total int64
	for _, entry := range entries {
		name := entry.Name()
		if err := validateFilename(name); err != nil {
			return nil, fmt.Errorf("invalid returned filename %q: %w", name, err)
		}
		if sensitiveFilename(name) {
			return nil, fmt.Errorf("returned file %q is blocked by the sensitive-file policy", name)
		}
		if forbiddenDeliverable(name) {
			return nil, fmt.Errorf("returned file %q is an archive or executable and cannot be transferred", name)
		}
		before, err := returnRoot.Lstat(name)
		if err != nil {
			return nil, fmt.Errorf("inspect returned file %q: %w", name, err)
		}
		if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
			return nil, fmt.Errorf("returned item %q must be a regular non-symlink file", name)
		}
		if err := privatefs.ValidateContainedRegularFile(filepath.Join(sandbox.ReturnDirectory, name)); err != nil {
			return nil, fmt.Errorf("returned file %q is not private: %w", name, err)
		}
		if goruntime.GOOS != "windows" && before.Mode().Perm()&0o111 != 0 {
			return nil, fmt.Errorf("returned file %q is executable and cannot be transferred", name)
		}
		if before.Size() > protocol.MaxAttachmentBytes {
			return nil, fmt.Errorf("returned file %q exceeds the %d-byte limit", name, protocol.MaxAttachmentBytes)
		}
		file, err := returnRoot.Open(name)
		if err != nil {
			return nil, fmt.Errorf("open returned file %q: %w", name, err)
		}
		opened, statErr := file.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
			_ = file.Close()
			return nil, fmt.Errorf("returned file %q changed during validation", name)
		}
		payload, readErr := io.ReadAll(io.LimitReader(file, protocol.MaxAttachmentBytes+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read returned file %q: %w", name, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close returned file %q: %w", name, closeErr)
		}
		after, err := returnRoot.Lstat(name)
		if err != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) {
			return nil, fmt.Errorf("returned file %q changed while it was read", name)
		}
		if int64(len(payload)) > protocol.MaxAttachmentBytes {
			return nil, fmt.Errorf("returned file %q exceeds the %d-byte limit", name, protocol.MaxAttachmentBytes)
		}
		total += int64(len(payload))
		if total > protocol.MaxRequestPayloadBytes {
			return nil, fmt.Errorf("returned files exceed the %d-byte total limit", protocol.MaxRequestPayloadBytes)
		}
		digest := sha256.Sum256(payload)
		mimeType := mime.TypeByExtension(strings.ToLower(filepath.Ext(name)))
		if mimeType == "" {
			mimeType = http.DetectContentType(payload)
		}
		if textualMIME(mimeType) && relayruntime.RedactSensitiveText(string(payload)) != string(payload) {
			return nil, fmt.Errorf("returned file %q contains credential-shaped text and cannot be transferred", name)
		}
		results = append(results, protocol.AttachmentInput{
			Name: name, MIMEType: mimeType, Encoding: "base64", SizeBytes: int64(len(payload)),
			SHA256: hex.EncodeToString(digest[:]), ContentBase64: base64.StdEncoding.EncodeToString(payload),
		})
	}
	if err := m.validateOwnedReturnRoot(sandbox, returnRoot); err != nil {
		return nil, err
	}
	return results, nil
}

func (m *Manager) openOwnedReturnRoot(sandbox *Sandbox) (*os.Root, error) {
	if sandbox.returnInfo == nil {
		return nil, errors.New("artifact return directory identity is unavailable")
	}
	relative := filepath.Join(sandbox.name, "return-files")
	current, err := m.root.Lstat(relative)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(sandbox.returnInfo, current) {
		return nil, errors.New("artifact return directory was replaced")
	}
	if err := privatefs.ValidateDirectory(sandbox.ReturnDirectory); err != nil {
		return nil, fmt.Errorf("artifact return directory is not private: %w", err)
	}
	opened, err := m.root.OpenRoot(relative)
	if err != nil {
		return nil, err
	}
	if err := m.validateOwnedReturnRoot(sandbox, opened); err != nil {
		_ = opened.Close()
		return nil, err
	}
	return opened, nil
}

func (m *Manager) validateOwnedReturnRoot(sandbox *Sandbox, opened *os.Root) error {
	if sandbox.returnInfo == nil || opened == nil {
		return errors.New("artifact return directory identity is unavailable")
	}
	openedInfo, statErr := opened.Stat(".")
	current, lstatErr := m.root.Lstat(filepath.Join(sandbox.name, "return-files"))
	if statErr != nil || lstatErr != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		!os.SameFile(sandbox.returnInfo, openedInfo) || !os.SameFile(sandbox.returnInfo, current) {
		return errors.New("artifact return directory changed during validation")
	}
	return nil
}

func textualMIME(value string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	return strings.HasPrefix(mediaType, "text/") || mediaType == "application/json" || mediaType == "application/xml" ||
		mediaType == "application/yaml" || mediaType == "application/x-yaml" || mediaType == "application/javascript"
}

func (m *Manager) Cleanup(sandbox *Sandbox) error {
	if err := m.validateSandbox(sandbox); err != nil {
		return err
	}
	if err := removeAll(m.root, sandbox.name); err != nil {
		return fmt.Errorf("remove request artifact directory: %w", err)
	}
	return nil
}

// removeAll is the Go 1.24-compatible equivalent of Root.RemoveAll. Every
// lookup remains beneath an already-open os.Root and symlinks are removed as
// links rather than traversed.
func removeAll(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return root.Remove(name)
	}
	directoryFile, err := root.Open(name)
	if err != nil {
		return err
	}
	if err := directoryFile.Chmod(0o700); err != nil {
		_ = directoryFile.Close()
		return err
	}
	if err := directoryFile.Close(); err != nil {
		return err
	}
	directory, err := root.OpenRoot(name)
	if err != nil {
		return err
	}
	entries, readErr := fs.ReadDir(directory.FS(), ".")
	if readErr == nil {
		for _, entry := range entries {
			if err := removeAll(directory, entry.Name()); err != nil {
				readErr = err
				break
			}
		}
	}
	closeErr := directory.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	return root.Remove(name)
}

func (m *Manager) createRequestDirectory() (string, error) {
	for attempt := 0; attempt < 10; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", fmt.Errorf("generate request directory name: %w", err)
		}
		name := requestDirectoryPrefix + hex.EncodeToString(random[:])
		if err := privatefs.CreateDirectory(filepath.Join(m.basePath, name)); err == nil {
			return name, nil
		} else if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("create request artifact directory: %w", err)
		}
	}
	return "", errors.New("could not allocate a unique request artifact directory")
}

func (m *Manager) validateSandbox(sandbox *Sandbox) error {
	if m == nil || m.root == nil || sandbox == nil || !strings.HasPrefix(sandbox.name, requestDirectoryPrefix) ||
		!fs.ValidPath(sandbox.name) || strings.ContainsAny(sandbox.name, `/\\`) ||
		filepath.Clean(sandbox.Root) != filepath.Join(m.basePath, sandbox.name) ||
		filepath.Clean(sandbox.ReturnDirectory) != filepath.Join(m.basePath, sandbox.name, "return-files") {
		return errors.New("artifact sandbox is not owned by this manager")
	}
	return nil
}

func validateDescriptors(descriptors []protocol.ArtifactDescriptor) error {
	seenIDs := make(map[string]struct{}, len(descriptors))
	seenNames := make(map[string]struct{}, len(descriptors))
	var total int64
	for _, descriptor := range descriptors {
		if strings.TrimSpace(descriptor.ArtifactID) == "" {
			return errors.New("attachment descriptor has no artifact_id")
		}
		if err := validateFilename(descriptor.Name); err != nil {
			return fmt.Errorf("attachment descriptor filename: %w", err)
		}
		if descriptor.SizeBytes < 0 || descriptor.SizeBytes > protocol.MaxAttachmentBytes {
			return fmt.Errorf("attachment %q has an invalid size", descriptor.Name)
		}
		if len(descriptor.SHA256) != sha256.Size*2 {
			return fmt.Errorf("attachment %q has an invalid SHA-256", descriptor.Name)
		}
		if _, err := hex.DecodeString(descriptor.SHA256); err != nil {
			return fmt.Errorf("attachment %q has an invalid SHA-256", descriptor.Name)
		}
		idKey, nameKey := descriptor.ArtifactID, strings.ToLower(descriptor.Name)
		if _, exists := seenIDs[idKey]; exists {
			return fmt.Errorf("duplicate attachment artifact_id %q", descriptor.ArtifactID)
		}
		if _, exists := seenNames[nameKey]; exists {
			return fmt.Errorf("duplicate attachment filename %q", descriptor.Name)
		}
		seenIDs[idKey], seenNames[nameKey] = struct{}{}, struct{}{}
		total += descriptor.SizeBytes
		if total > protocol.MaxRequestPayloadBytes {
			return fmt.Errorf("attachments exceed the %d-byte total limit", protocol.MaxRequestPayloadBytes)
		}
	}
	return nil
}

func verifyContent(expected protocol.ArtifactDescriptor, content *protocol.ArtifactContent) ([]byte, error) {
	if content == nil || content.ArtifactDescriptor != expected {
		return nil, errors.New("relay artifact metadata does not match the approved descriptor")
	}
	if content.Encoding != "base64" {
		return nil, errors.New("relay artifact encoding must be base64")
	}
	payload, err := base64.StdEncoding.DecodeString(content.ContentBase64)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	if int64(len(payload)) != expected.SizeBytes || int64(len(payload)) > protocol.MaxAttachmentBytes {
		return nil, errors.New("decoded size does not match the approved descriptor")
	}
	digest := sha256.Sum256(payload)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), expected.SHA256) {
		return nil, errors.New("decoded SHA-256 does not match the approved descriptor")
	}
	return payload, nil
}

func validateFilename(name string) error {
	return protocol.ValidatePortableFilename(name)
}

func sensitiveFilename(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case ".env", ".netrc", ".npmrc", ".pypirc", ".gitconfig", ".git-credentials",
		"credentials", "credentials.json", "id_rsa", "id_ed25519", "known_hosts", "authorized_keys":
		return true
	}
	if strings.HasPrefix(lower, ".env.") {
		return true
	}
	for _, suffix := range []string{".pem", ".key", ".p12", ".pfx", ".kdbx"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func forbiddenDeliverable(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".exe", ".com", ".bat", ".cmd", ".ps1", ".sh", ".msi", ".app", ".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}
