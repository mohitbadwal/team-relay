package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/protocol"
)

type mapFetcher map[string]*protocol.ArtifactContent

func (m mapFetcher) FetchArtifact(_ context.Context, id string) (*protocol.ArtifactContent, error) {
	value, ok := m[id]
	if !ok {
		return nil, errors.New("missing")
	}
	copy := *value
	return &copy, nil
}

func TestMaterializeCollectAndCleanup(t *testing.T) {
	t.Parallel()
	manager, err := NewManager(filepath.Join(t.TempDir(), "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	descriptor, content := testArtifact("art_1", "notes.txt", []byte("approved input"))
	sandbox, err := manager.Materialize(context.Background(), []protocol.ArtifactDescriptor{descriptor}, mapFetcher{"art_1": content})
	if err != nil {
		t.Fatal(err)
	}
	if len(sandbox.Attachments) != 1 {
		t.Fatalf("attachments = %#v", sandbox.Attachments)
	}
	for _, path := range []string{sandbox.Root, sandbox.ReturnDirectory} {
		if err := privatefs.ValidateDirectory(path); err != nil {
			t.Fatalf("artifact directory %s is not private: %v", path, err)
		}
	}
	if err := privatefs.ValidateRegularFile(sandbox.Attachments[0]); err != nil {
		t.Fatalf("materialized attachment is not private: %v", err)
	}
	got, err := os.ReadFile(sandbox.Attachments[0])
	if err != nil || string(got) != "approved input" {
		t.Fatalf("materialized attachment = %q, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(sandbox.Attachments[0])
		if info.Mode().Perm() != 0o400 {
			t.Fatalf("attachment permissions = %o", info.Mode().Perm())
		}
	}
	if err := os.WriteFile(filepath.Join(sandbox.ReturnDirectory, "findings.md"), []byte("# Findings\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	results, err := manager.CollectResults(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Name != "findings.md" || results[0].ContentBase64 != base64.StdEncoding.EncodeToString([]byte("# Findings\n")) {
		t.Fatalf("results = %#v", results)
	}
	if err := manager.Cleanup(sandbox); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sandbox.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sandbox was not removed: %v", err)
	}
}

func TestMaterializeRejectsDescriptorMismatchAndCleansUp(t *testing.T) {
	t.Parallel()
	base := filepath.Join(t.TempDir(), "runtime")
	manager, err := NewManager(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	descriptor, content := testArtifact("art_1", "notes.txt", []byte("input"))
	content.SHA256 = strings.Repeat("0", 64)
	if _, err := manager.Materialize(context.Background(), []protocol.ArtifactDescriptor{descriptor}, mapFetcher{"art_1": content}); err == nil {
		t.Fatal("expected descriptor mismatch")
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed sandbox was not cleaned: %#v, %v", entries, err)
	}
}

func TestCollectRejectsUnsafeReturnedItems(t *testing.T) {
	t.Parallel()
	manager, err := NewManager(filepath.Join(t.TempDir(), "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	sandbox, err := manager.Materialize(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Cleanup(sandbox) })
	if err := os.WriteFile(filepath.Join(sandbox.ReturnDirectory, ".env"), []byte("SECRET=value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CollectResults(sandbox); err == nil || !strings.Contains(err.Error(), "sensitive-file") {
		t.Fatalf("expected sensitive-file rejection, got %v", err)
	}
	if err := os.Remove(filepath.Join(sandbox.ReturnDirectory, ".env")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(sandbox.ReturnDirectory, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CollectResults(sandbox); err == nil || !strings.Contains(err.Error(), "regular non-symlink") {
		t.Fatalf("expected directory rejection, got %v", err)
	}
}

func TestCollectRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is permission-dependent on Windows")
	}
	t.Parallel()
	manager, err := NewManager(filepath.Join(t.TempDir(), "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	sandbox, err := manager.Materialize(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Cleanup(sandbox) })
	target := filepath.Join(sandbox.Root, "target.txt")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(sandbox.ReturnDirectory, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CollectResults(sandbox); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestCollectRejectsReplacedReturnDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is permission-dependent on Windows")
	}
	t.Parallel()

	manager, err := NewManager(filepath.Join(t.TempDir(), "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	victim, err := manager.Materialize(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Cleanup(victim) })
	attacker, err := manager.Materialize(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Cleanup(attacker) })
	if err := os.WriteFile(filepath.Join(victim.ReturnDirectory, "other-request.txt"), []byte("must not cross requests"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(attacker.ReturnDirectory); err != nil {
		t.Fatal(err)
	}
	relativeTarget := filepath.Join("..", filepath.Base(victim.Root), "return-files")
	if err := os.Symlink(relativeTarget, attacker.ReturnDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CollectResults(attacker); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("CollectResults error = %v, want replaced-directory rejection", err)
	}
}

func TestReturnedFilenameValidationIsPortable(t *testing.T) {
	t.Parallel()

	for _, name := range []string{`nested\report.txt`, "report:stream.txt", "NUL.txt", "COM1.log", "report.txt.", "report.txt "} {
		if err := validateFilename(name); err == nil {
			t.Fatalf("validateFilename(%q) succeeded", name)
		}
	}
}

func testArtifact(id, name string, payload []byte) (protocol.ArtifactDescriptor, *protocol.ArtifactContent) {
	digest := sha256.Sum256(payload)
	descriptor := protocol.ArtifactDescriptor{
		ArtifactID: id, Name: name, MIMEType: "text/plain", SizeBytes: int64(len(payload)), SHA256: hex.EncodeToString(digest[:]),
	}
	return descriptor, &protocol.ArtifactContent{
		ArtifactDescriptor: descriptor, Encoding: "base64", ContentBase64: base64.StdEncoding.EncodeToString(payload),
	}
}
