package mcpserver

import (
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
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mohitbadwal/team-relay/internal/protocol"
)

type LocalAttachment struct {
	WorkspaceAlias string `json:"workspace_alias" jsonschema:"Locally configured workspace alias containing the file"`
	RelativePath   string `json:"relative_path" jsonschema:"Slash-separated path beneath the workspace alias"`
}

type DownloadedFile struct {
	WorkspaceAlias string `json:"workspace_alias"`
	RelativePath   string `json:"relative_path"`
	Name           string `json:"name"`
	MIMEType       string `json:"mime_type"`
	SizeBytes      int64  `json:"size_bytes"`
	SHA256         string `json:"sha256"`
}

type AttachmentOptions struct {
	OutboundEnabled bool
	Workspaces      map[string]string
}

type attachmentStore struct {
	outboundEnabled bool
	roots           map[string]*attachmentWorkspace
}

const downloadDirectory = "team-relay-downloads"

type attachmentWorkspace struct {
	root *os.Root

	downloadMu   sync.Mutex
	downloadRoot *os.Root
}

func newAttachmentStore(options AttachmentOptions) (*attachmentStore, error) {
	store := &attachmentStore{outboundEnabled: options.OutboundEnabled, roots: make(map[string]*attachmentWorkspace, len(options.Workspaces))}
	seenAliases := make(map[string]struct{}, len(options.Workspaces))
	for rawAlias, rootPath := range options.Workspaces {
		alias := strings.TrimSpace(rawAlias)
		if alias == "" || strings.ContainsAny(alias, "/\\") {
			store.close()
			return nil, fmt.Errorf("invalid workspace alias %q", rawAlias)
		}
		if strings.TrimSpace(rootPath) == "" {
			store.close()
			return nil, fmt.Errorf("workspace %q has an empty path", alias)
		}
		aliasKey := strings.ToLower(alias)
		if _, exists := seenAliases[aliasKey]; exists {
			store.close()
			return nil, fmt.Errorf("duplicate workspace alias %q", rawAlias)
		}
		seenAliases[aliasKey] = struct{}{}
		absolute, err := filepath.Abs(rootPath)
		if err != nil {
			store.close()
			return nil, fmt.Errorf("resolve workspace %q: %w", alias, err)
		}
		// Pin a configured alias to its canonical directory. Relative attachment
		// paths are then checked component-by-component beneath this open root.
		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			store.close()
			return nil, fmt.Errorf("resolve workspace %q links: %w", alias, err)
		}
		root, err := os.OpenRoot(resolved)
		if err != nil {
			store.close()
			return nil, fmt.Errorf("open workspace %q: %w", alias, err)
		}
		store.roots[alias] = &attachmentWorkspace{root: root}
	}
	return store, nil
}

func (s *attachmentStore) close() {
	for _, workspace := range s.roots {
		workspace.downloadMu.Lock()
		if workspace.downloadRoot != nil {
			_ = workspace.downloadRoot.Close()
			workspace.downloadRoot = nil
		}
		workspace.downloadMu.Unlock()
		_ = workspace.root.Close()
	}
}

func (s *attachmentStore) prepare(inputs []LocalAttachment) ([]protocol.AttachmentInput, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	if !s.outboundEnabled {
		return nil, fmt.Errorf("outbound attachments are disabled by the workstation owner")
	}
	if len(inputs) > protocol.MaxAttachments {
		return nil, fmt.Errorf("at most %d attachments are allowed", protocol.MaxAttachments)
	}

	result := make([]protocol.AttachmentInput, 0, len(inputs))
	seenNames := make(map[string]struct{}, len(inputs))
	var total int64
	for _, input := range inputs {
		item, err := s.prepareOne(input)
		if err != nil {
			return nil, err
		}
		nameKey := strings.ToLower(item.Name)
		if _, exists := seenNames[nameKey]; exists {
			return nil, fmt.Errorf("duplicate attachment filename %q", item.Name)
		}
		seenNames[nameKey] = struct{}{}
		total += item.SizeBytes
		if total > protocol.MaxRequestPayloadBytes {
			return nil, fmt.Errorf("attachments exceed the %d-byte total limit", protocol.MaxRequestPayloadBytes)
		}
		result = append(result, item)
	}
	return result, nil
}

func (s *attachmentStore) prepareOne(input LocalAttachment) (protocol.AttachmentInput, error) {
	workspace, relativePath, err := s.resolve(input.WorkspaceAlias, input.RelativePath)
	if err != nil {
		return protocol.AttachmentInput{}, err
	}
	if sensitivePath(relativePath) {
		return protocol.AttachmentInput{}, fmt.Errorf("attachment %q is blocked by the sensitive-file policy", relativePath)
	}
	file, err := openRegularWithoutSymlinks(workspace.root, relativePath)
	if err != nil {
		return protocol.AttachmentInput{}, fmt.Errorf("open attachment %q: %w", relativePath, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return protocol.AttachmentInput{}, fmt.Errorf("inspect attachment %q: %w", relativePath, err)
	}
	if !info.Mode().IsRegular() {
		return protocol.AttachmentInput{}, fmt.Errorf("attachment %q is not a regular file", relativePath)
	}
	if info.Size() > protocol.MaxAttachmentBytes {
		return protocol.AttachmentInput{}, fmt.Errorf("attachment %q exceeds the %d-byte limit", relativePath, protocol.MaxAttachmentBytes)
	}
	payload, err := io.ReadAll(io.LimitReader(file, protocol.MaxAttachmentBytes+1))
	if err != nil {
		return protocol.AttachmentInput{}, fmt.Errorf("read attachment %q: %w", relativePath, err)
	}
	if int64(len(payload)) > protocol.MaxAttachmentBytes {
		return protocol.AttachmentInput{}, fmt.Errorf("attachment %q exceeds the %d-byte limit", relativePath, protocol.MaxAttachmentBytes)
	}
	digest := sha256.Sum256(payload)
	mimeType := mime.TypeByExtension(path.Ext(relativePath))
	if mimeType == "" {
		mimeType = http.DetectContentType(payload)
	}
	return protocol.AttachmentInput{
		Name:          path.Base(relativePath),
		MIMEType:      mimeType,
		Encoding:      "base64",
		SizeBytes:     int64(len(payload)),
		SHA256:        hex.EncodeToString(digest[:]),
		ContentBase64: base64.StdEncoding.EncodeToString(payload),
	}, nil
}

func (s *attachmentStore) save(alias, relativePath string, content *protocol.ArtifactContent) (DownloadedFile, error) {
	workspace, filename, err := s.resolveDownload(alias, relativePath)
	if err != nil {
		return DownloadedFile{}, err
	}
	if content == nil || content.Encoding != "base64" {
		return DownloadedFile{}, fmt.Errorf("returned artifact must use base64 encoding")
	}
	if err := protocol.ValidatePortableFilename(content.Name); err != nil || sensitivePath(content.Name) {
		return DownloadedFile{}, fmt.Errorf("returned artifact has a blocked filename")
	}
	payload, err := base64.StdEncoding.DecodeString(content.ContentBase64)
	if err != nil {
		return DownloadedFile{}, fmt.Errorf("decode returned artifact: %w", err)
	}
	if int64(len(payload)) != content.SizeBytes || int64(len(payload)) > protocol.MaxAttachmentBytes {
		return DownloadedFile{}, fmt.Errorf("returned artifact size does not match its descriptor")
	}
	digest := sha256.Sum256(payload)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), content.SHA256) {
		return DownloadedFile{}, fmt.Errorf("returned artifact checksum does not match its descriptor")
	}
	downloadRoot, err := workspace.openDownloadRoot()
	if err != nil {
		return DownloadedFile{}, err
	}
	file, err := downloadRoot.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return DownloadedFile{}, fmt.Errorf("create destination without overwriting: %w", err)
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		_ = downloadRoot.Remove(filename)
		return DownloadedFile{}, fmt.Errorf("write returned artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = downloadRoot.Remove(filename)
		return DownloadedFile{}, fmt.Errorf("close returned artifact: %w", err)
	}
	if err := workspace.validateDownloadRoot(downloadRoot); err != nil {
		_ = downloadRoot.Remove(filename)
		return DownloadedFile{}, err
	}
	return DownloadedFile{
		WorkspaceAlias: strings.TrimSpace(alias),
		RelativePath:   path.Join(downloadDirectory, filename),
		Name:           content.Name,
		MIMEType:       content.MIMEType,
		SizeBytes:      content.SizeBytes,
		SHA256:         content.SHA256,
	}, nil
}

func (s *attachmentStore) resolve(alias, relativePath string) (*attachmentWorkspace, string, error) {
	alias = strings.TrimSpace(alias)
	workspace, ok := s.roots[alias]
	if !ok {
		return nil, "", fmt.Errorf("unknown workspace alias %q", alias)
	}
	if err := protocol.ValidatePortableRelativePath(relativePath); err != nil {
		return nil, "", fmt.Errorf("invalid attachment path: %w", err)
	}
	return workspace, relativePath, nil
}

func (s *attachmentStore) resolveDownload(alias, relativePath string) (*attachmentWorkspace, string, error) {
	alias = strings.TrimSpace(alias)
	workspace, ok := s.roots[alias]
	if !ok {
		return nil, "", fmt.Errorf("unknown workspace alias %q", alias)
	}
	filename := relativePath
	if err := protocol.ValidatePortableFilename(filename); err != nil {
		return nil, "", fmt.Errorf("download destination must be one portable filename beneath %s: %w", downloadDirectory, err)
	}
	if sensitivePath(filename) {
		return nil, "", fmt.Errorf("download destination filename is blocked by the sensitive-file policy")
	}
	return workspace, filename, nil
}

func (w *attachmentWorkspace) openDownloadRoot() (*os.Root, error) {
	w.downloadMu.Lock()
	defer w.downloadMu.Unlock()
	if w.downloadRoot != nil {
		if err := w.validateDownloadRootLocked(w.downloadRoot); err != nil {
			return nil, err
		}
		return w.downloadRoot, nil
	}

	before, err := w.root.Lstat(downloadDirectory)
	if errors.Is(err, fs.ErrNotExist) {
		if err := w.root.Mkdir(downloadDirectory, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("create dedicated download directory: %w", err)
		}
		before, err = w.root.Lstat(downloadDirectory)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect dedicated download directory: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, fmt.Errorf("dedicated download path %q must be a non-symlink directory", downloadDirectory)
	}
	opened, err := w.root.OpenRoot(downloadDirectory)
	if err != nil {
		return nil, fmt.Errorf("open dedicated download directory: %w", err)
	}
	openedInfo, statErr := opened.Stat(".")
	after, lstatErr := w.root.Lstat(downloadDirectory)
	if statErr != nil || lstatErr != nil || after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, openedInfo) || !os.SameFile(before, after) {
		_ = opened.Close()
		return nil, fmt.Errorf("dedicated download directory changed during validation")
	}
	w.downloadRoot = opened
	return w.downloadRoot, nil
}

func (w *attachmentWorkspace) validateDownloadRoot(expected *os.Root) error {
	w.downloadMu.Lock()
	defer w.downloadMu.Unlock()
	if w.downloadRoot == nil || w.downloadRoot != expected {
		return fmt.Errorf("dedicated download directory handle is no longer active")
	}
	return w.validateDownloadRootLocked(expected)
}

func (w *attachmentWorkspace) validateDownloadRootLocked(opened *os.Root) error {
	openedInfo, statErr := opened.Stat(".")
	current, lstatErr := w.root.Lstat(downloadDirectory)
	if statErr != nil || lstatErr != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(openedInfo, current) {
		return fmt.Errorf("dedicated download directory changed during validation")
	}
	return nil
}

// openRegularWithoutSymlinks walks each directory using a pinned Root handle,
// rejects links before and after opening, and verifies that each opened handle
// refers to the lstat'd object. Bytes are read only from the final verified file
// handle, so parent renames cannot redirect the read after validation.
func openRegularWithoutSymlinks(root *os.Root, relativePath string) (*os.File, error) {
	components := strings.Split(relativePath, "/")
	current := root
	openedRoots := make([]*os.Root, 0, len(components)-1)
	defer func() {
		for index := len(openedRoots) - 1; index >= 0; index-- {
			_ = openedRoots[index].Close()
		}
	}()

	for _, component := range components[:len(components)-1] {
		before, err := current.Lstat(component)
		if err != nil {
			return nil, err
		}
		if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			return nil, fmt.Errorf("path component %q must be a non-symlink directory", component)
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			return nil, err
		}
		openedInfo, statErr := next.Stat(".")
		after, lstatErr := current.Lstat(component)
		if statErr != nil || lstatErr != nil || after.Mode()&os.ModeSymlink != 0 ||
			!os.SameFile(before, openedInfo) || !os.SameFile(before, after) {
			_ = next.Close()
			return nil, fmt.Errorf("path component %q changed during validation", component)
		}
		openedRoots = append(openedRoots, next)
		current = next
	}

	filename := components[len(components)-1]
	before, err := current.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("file must be regular and must not be a symlink")
	}
	file, err := current.Open(filename)
	if err != nil {
		return nil, err
	}
	openedInfo, statErr := file.Stat()
	after, lstatErr := current.Lstat(filename)
	if statErr != nil || lstatErr != nil || after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, openedInfo) || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, fmt.Errorf("file changed during validation")
	}
	return file, nil
}

func sensitivePath(relativePath string) bool {
	for _, component := range strings.Split(strings.ToLower(relativePath), "/") {
		switch component {
		case ".env", ".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker", ".git", ".hg", ".svn", ".claude", ".codex", ".team-relay",
			".netrc", ".npmrc", ".pypirc", ".gitconfig", ".git-credentials",
			"credentials", "credentials.json", "id_rsa", "id_ed25519", "known_hosts", "authorized_keys":
			return true
		}
		if strings.HasPrefix(component, ".env.") || strings.HasSuffix(component, ".pem") || strings.HasSuffix(component, ".key") || strings.HasSuffix(component, ".p12") ||
			strings.HasSuffix(component, ".pfx") || strings.HasSuffix(component, ".kdbx") {
			return true
		}
	}
	return false
}
