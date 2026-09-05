package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateWorkDirReturnsCanonicalSymlinkTarget(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "workspace")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	got, err := ValidateWorkDir(link)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("canonical work dir = %q, want %q", got, want)
	}
}

func TestValidateWorkDirCanonicalPathDoesNotFollowLaterSymlinkRetarget(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	for _, directory := range []string{first, second} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "workspace")
	if err := os.Symlink(first, link); err != nil {
		t.Fatal(err)
	}

	validated, err := ValidateWorkDir(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, link); err != nil {
		t.Fatal(err)
	}

	firstCanonical, err := filepath.EvalSymlinks(first)
	if err != nil {
		t.Fatal(err)
	}
	secondCanonical, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}
	if validated != firstCanonical || validated == secondCanonical {
		t.Fatalf("validated path changed scope after retarget: got %q, first %q, second %q", validated, firstCanonical, secondCanonical)
	}
}
