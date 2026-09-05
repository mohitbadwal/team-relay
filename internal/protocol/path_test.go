package protocol

import "testing"

func TestValidatePortableFilename(t *testing.T) {
	t.Parallel()

	valid := []string{"report.md", "analysis 2026.txt", "résumé.pdf", "COM10.txt"}
	for _, name := range valid {
		name := name
		t.Run("valid_"+name, func(t *testing.T) {
			t.Parallel()
			if err := ValidatePortableFilename(name); err != nil {
				t.Fatalf("ValidatePortableFilename(%q) = %v", name, err)
			}
		})
	}

	invalid := []string{
		"", ".", "..", " report.txt", "report.txt ", "report.", "nested/report.txt", `nested\report.txt`,
		"report:secret.txt", "report?.txt", "NUL", "nul.txt", "COM1.log", "COM².log", "lpt9", "LPT³", "CONOUT$.txt", "line\nfeed.txt",
	}
	for _, name := range invalid {
		name := name
		t.Run("invalid_"+name, func(t *testing.T) {
			t.Parallel()
			if err := ValidatePortableFilename(name); err == nil {
				t.Fatalf("ValidatePortableFilename(%q) succeeded", name)
			}
		})
	}
}

func TestValidatePortableRelativePath(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"src/report.md", "report.md"} {
		if err := ValidatePortableRelativePath(value); err != nil {
			t.Fatalf("ValidatePortableRelativePath(%q) = %v", value, err)
		}
	}
	for _, value := range []string{"../report.md", "/tmp/report.md", `src\report.md`, "src/NUL.txt", "src/report.txt."} {
		if err := ValidatePortableRelativePath(value); err == nil {
			t.Fatalf("ValidatePortableRelativePath(%q) succeeded", value)
		}
	}
}
