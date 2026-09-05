package mcpserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/mohitbadwal/team-relay/internal/protocol"
)

func TestPrepareAttachmentIsAliasBounded(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "safe.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newAttachmentStore(AttachmentOptions{OutboundEnabled: true, Workspaces: map[string]string{"repo": root}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	items, err := store.prepare([]LocalAttachment{{WorkspaceAlias: "repo", RelativePath: "safe.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].SizeBytes != 5 {
		t.Fatalf("unexpected attachment: %#v", items)
	}
	if _, err := store.prepare([]LocalAttachment{{WorkspaceAlias: "repo", RelativePath: "../outside"}}); err == nil {
		t.Fatal("expected traversal to be rejected")
	}
}

func TestAttachmentStoreRejectsEmptyWorkspacePath(t *testing.T) {
	t.Parallel()
	if _, err := newAttachmentStore(AttachmentOptions{Workspaces: map[string]string{"repo": ""}}); err == nil {
		t.Fatal("expected empty workspace path to be rejected")
	}
}

func TestSensitiveAttachmentIsRejected(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("SECRET=x"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newAttachmentStore(AttachmentOptions{OutboundEnabled: true, Workspaces: map[string]string{"repo": root}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if _, err := store.prepare([]LocalAttachment{{WorkspaceAlias: "repo", RelativePath: ".env"}}); err == nil {
		t.Fatal("expected sensitive file to be rejected")
	}
}

func TestPrepareRejectsSymlinkFileAndDirectoryComponents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is permission-dependent on Windows")
	}
	t.Parallel()

	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDirectory, "report.txt"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(realDirectory, "report.txt"), filepath.Join(root, "file-link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDirectory, filepath.Join(root, "dir-link")); err != nil {
		t.Fatal(err)
	}
	store, err := newAttachmentStore(AttachmentOptions{OutboundEnabled: true, Workspaces: map[string]string{"repo": root}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	for _, candidate := range []string{"file-link.txt", "dir-link/report.txt"} {
		if _, err := store.prepare([]LocalAttachment{{WorkspaceAlias: "repo", RelativePath: candidate}}); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("prepare(%q) error = %v, want symlink rejection", candidate, err)
		}
	}
}

func TestPrepareRejectsPortableAndControlPaths(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store, err := newAttachmentStore(AttachmentOptions{OutboundEnabled: true, Workspaces: map[string]string{"repo": root}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	for _, candidate := range []string{`folder\report.txt`, "report:stream.txt", "NUL.txt", "report.txt.", "report.txt ", ".git/config", ".claude/settings.json", ".env.local", ".docker/config.json", ".npmrc"} {
		if _, err := store.prepare([]LocalAttachment{{WorkspaceAlias: "repo", RelativePath: candidate}}); err == nil {
			t.Fatalf("prepare(%q) succeeded", candidate)
		}
	}
}

func TestSaveUsesDedicatedDirectoryAndNeverOverwrites(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store, err := newAttachmentStore(AttachmentOptions{Workspaces: map[string]string{"repo": root}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	content := returnedContent("report.md", []byte("# Result\n"))
	downloaded, err := store.save("repo", "answer.md", content)
	if err != nil {
		t.Fatal(err)
	}
	if downloaded.RelativePath != "team-relay-downloads/answer.md" {
		t.Fatalf("RelativePath = %q", downloaded.RelativePath)
	}
	payload, err := os.ReadFile(filepath.Join(root, "team-relay-downloads", "answer.md"))
	if err != nil || string(payload) != "# Result\n" {
		t.Fatalf("saved payload = %q, %v", payload, err)
	}
	if _, err := store.save("repo", "answer.md", content); err == nil || !strings.Contains(err.Error(), "without overwriting") {
		t.Fatalf("second save error = %v, want no-overwrite rejection", err)
	}
	for _, candidate := range []string{"../CLAUDE.md", ".claude/settings.json", `nested\file.md`, "report:stream.md", "CON.md", "trailing.", "trailing "} {
		if _, err := store.save("repo", candidate, content); err == nil {
			t.Fatalf("save destination %q succeeded", candidate)
		}
	}
}

func TestSaveRejectsSymlinkedDedicatedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is permission-dependent on Windows")
	}
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, downloadDirectory)); err != nil {
		t.Fatal(err)
	}
	store, err := newAttachmentStore(AttachmentOptions{Workspaces: map[string]string{"repo": root}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if _, err := store.save("repo", "report.md", returnedContent("report.md", []byte("data"))); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("save error = %v, want symlink rejection", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "report.md")); !os.IsNotExist(err) {
		t.Fatalf("outside path was written: %v", err)
	}
}

func TestSaveRejectsDedicatedDirectoryReplacementAfterOpen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is permission-dependent on Windows")
	}
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	store, err := newAttachmentStore(AttachmentOptions{Workspaces: map[string]string{"repo": root}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if _, err := store.save("repo", "first.txt", returnedContent("first.txt", []byte("first"))); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "moved-downloads")
	if err := os.Rename(filepath.Join(root, downloadDirectory), moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, downloadDirectory)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.save("repo", "second.txt", returnedContent("second.txt", []byte("second"))); err == nil || !strings.Contains(err.Error(), "changed during validation") {
		t.Fatalf("save error = %v, want replaced-directory rejection", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "second.txt")); !os.IsNotExist(err) {
		t.Fatalf("replacement symlink target was written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(moved, "second.txt")); !os.IsNotExist(err) {
		t.Fatalf("orphaned original directory retained rejected write: %v", err)
	}
}

func TestConcurrentSaveNeverOverwrites(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store, err := newAttachmentStore(AttachmentOptions{Workspaces: map[string]string{"repo": root}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	contents := []*protocol.ArtifactContent{
		returnedContent("first.txt", []byte("first")),
		returnedContent("second.txt", []byte("second")),
	}
	start := make(chan struct{})
	errorsByAttempt := make(chan error, len(contents))
	var wait sync.WaitGroup
	for _, content := range contents {
		content := content
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := store.save("repo", "answer.txt", content)
			errorsByAttempt <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByAttempt)
	successes := 0
	failures := 0
	for err := range errorsByAttempt {
		if err == nil {
			successes++
		} else if strings.Contains(err.Error(), "without overwriting") {
			failures++
		} else {
			t.Fatalf("unexpected save error: %v", err)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("save outcomes successes=%d failures=%d", successes, failures)
	}
	payload, err := os.ReadFile(filepath.Join(root, downloadDirectory, "answer.txt"))
	if err != nil || (string(payload) != "first" && string(payload) != "second") {
		t.Fatalf("saved payload = %q, %v", payload, err)
	}
}

func returnedContent(name string, payload []byte) *protocol.ArtifactContent {
	digest := sha256.Sum256(payload)
	return &protocol.ArtifactContent{
		ArtifactDescriptor: protocol.ArtifactDescriptor{
			ArtifactID: "art_1", Name: name, MIMEType: "text/plain", SizeBytes: int64(len(payload)), SHA256: hex.EncodeToString(digest[:]),
		},
		Encoding: "base64", ContentBase64: base64.StdEncoding.EncodeToString(payload),
	}
}
