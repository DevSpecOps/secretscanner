package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockEngine implements RuleEngine for testing
type mockEngine struct{}

func (m mockEngine) Detect(line string) (string, string, bool) {
	if strings.Contains(line, "SECRET") {
		return "SECRET", "TEST001", true
	}
	return "", "", false
}

func TestScan_FindsSecrets(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file with a secret
	secretFile := filepath.Join(tmpDir, "secret.txt")
	err := os.WriteFile(secretFile, []byte("This is a SECRET string\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create a clean file
	cleanFile := filepath.Join(tmpDir, "clean.txt")
	err = os.WriteFile(cleanFile, []byte("Nothing here\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	engine := mockEngine{}
	findings, err := Scan(tmpDir, engine)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}
	if findings[0].File != secretFile {
		t.Errorf("Expected secret file %s, got %s", secretFile, findings[0].File)
	}
	if findings[0].RuleID != "TEST001" {
		t.Errorf("Expected rule TEST001, got %s", findings[0].RuleID)
	}
}

func TestScan_SkipsBinaryFiles(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a fake binary file (contains null byte)
	binaryFile := filepath.Join(tmpDir, "binary.bin")
	err := os.WriteFile(binaryFile, []byte{0x00, 0x01, 0x02}, 0644)
	if err != nil {
		t.Fatal(err)
	}
	engine := mockEngine{}
	findings, err := Scan(tmpDir, engine)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if f.File == binaryFile {
			t.Error("Binary file should be skipped")
		}
	}
}

func TestScan_SkipsDotGit(t *testing.T) {
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	err := os.Mkdir(gitDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	secretInsideGit := filepath.Join(gitDir, "secret.txt")
	err = os.WriteFile(secretInsideGit, []byte("SECRET"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	engine := mockEngine{}
	findings, err := Scan(tmpDir, engine)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.File, ".git") {
			t.Errorf("Found secret inside .git directory: %s", f.File)
		}
	}
}