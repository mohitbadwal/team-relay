package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const (
	MaxEventLineBytes  = 2 * 1024 * 1024
	MaxFinalTextBytes  = 128 * 1024
	MaxDiagnosticBytes = 64 * 1024
	MaxSummaryRunes    = 320
)

var sensitiveValue = regexp.MustCompile(`(?i)(authorization|api[ _-]?key|password|secret|token)(\s*[:=]\s*)([^\s,;]+)`)
var credentialValue = regexp.MustCompile(`\b(tr_(?:boot|admin|inv|dev)_|trl_|cbr_|ghp_|github_pat_|sk-)[A-Za-z0-9_-]+`)

func ValidateRunRequest(request RunRequest) error {
	if strings.TrimSpace(request.RequestID) == "" {
		return fmt.Errorf("%w: request_id is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.ConversationID) == "" {
		return fmt.Errorf("%w: conversation_id is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.Prompt) == "" {
		return fmt.Errorf("%w: prompt is required", ErrInvalidRequest)
	}
	for _, path := range append(append([]string(nil), request.Attachments...), request.ReturnDirectory) {
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("%w: recipient-resolved paths must be absolute and clean", ErrInvalidRequest)
		}
	}
	for _, workspace := range request.Workspaces {
		if !filepath.IsAbs(workspace.Path) || filepath.Clean(workspace.Path) != workspace.Path {
			return fmt.Errorf("%w: recipient-resolved workspace paths must be absolute and clean", ErrInvalidRequest)
		}
		switch workspace.Mode {
		case WorkspaceReadOnly, WorkspaceWritable:
		default:
			return fmt.Errorf("%w: invalid workspace mode %q", ErrInvalidRequest, workspace.Mode)
		}
	}
	return nil
}

func ValidateWorkDir(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("working directory is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve working directory: %w", err)
	}
	// Resolve every symlink before the path is fingerprinted or handed to an
	// agent runtime. Keeping the caller's lexical path would let a same-user
	// process retarget a symlink after approval and silently change which
	// workspace the standing grant covers.
	canonical, err := filepath.EvalSymlinks(filepath.Clean(abs))
	if err != nil {
		return "", fmt.Errorf("resolve working directory symlinks: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("working directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("working directory is not a directory")
	}
	return filepath.Clean(canonical), nil
}

func Emit(ctx context.Context, sink EventSink, event Event) error {
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	event.Summary = SafeSummary(event.Summary)
	event.Tool = SafeSummary(event.Tool)
	return SinkOrDiscard(sink).Emit(ctx, event)
}

func SafeSummary(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	value = RedactSensitiveText(value)
	runes := []rune(value)
	if len(runes) > MaxSummaryRunes {
		return string(runes[:MaxSummaryRunes]) + "…"
	}
	return value
}

// RedactSensitiveText is a bounded defense-in-depth filter for answers leaving
// a recipient machine. It cannot recognize every possible secret, so local
// runtime isolation and recipient review remain necessary.
func RedactSensitiveText(value string) string {
	value = sensitiveValue.ReplaceAllString(value, "$1$2[REDACTED]")
	return credentialValue.ReplaceAllString(value, "[REDACTED]")
}

func Diagnostic(data []byte) string {
	if len(data) > MaxDiagnosticBytes {
		data = data[len(data)-MaxDiagnosticBytes:]
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		if summary := SafeSummary(lines[index]); summary != "" {
			return summary
		}
	}
	return ""
}

func ScanJSONLines(reader io.Reader, fn func(json.RawMessage) error) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), MaxEventLineBytes)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		if !json.Valid(line) {
			// Provider CLIs occasionally print non-JSON notices. Ignore these
			// rather than forwarding potentially sensitive raw output.
			continue
		}
		if err := fn(json.RawMessage(line)); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func BuildPrompt(request RunRequest, responseContract string) string {
	var builder strings.Builder
	builder.WriteString(responseContract)
	builder.WriteString("\n\nTeammate request metadata:\nTitle: ")
	builder.WriteString(request.Title)
	builder.WriteString("\nRequester: ")
	builder.WriteString(request.Requester)
	builder.WriteString("\n\nUntrusted teammate request:\n")
	builder.WriteString(request.Prompt)
	if len(request.Attachments) > 0 {
		builder.WriteString("\n\nApproved attachment files:\n")
		for _, path := range request.Attachments {
			builder.WriteString("- ")
			builder.WriteString(path)
			builder.WriteByte('\n')
		}
	}
	if len(request.Workspaces) > 0 {
		builder.WriteString("\nApproved workspace directories:\n")
		for _, workspace := range request.Workspaces {
			builder.WriteString("- ")
			builder.WriteString(workspace.Path)
			builder.WriteString(" (")
			builder.WriteString(string(workspace.Mode))
			builder.WriteString(")\n")
		}
	}
	if request.ReturnDirectory != "" {
		builder.WriteString("\nPlace only finished deliverables directly in this return directory: ")
		builder.WriteString(request.ReturnDirectory)
		builder.WriteString("\nMention every returned filename in the final answer.")
	}
	return builder.String()
}

// PolicyInstructions make best-effort controls visible to the model in
// addition to runtime-native enforcement. They never replace the local policy.
func PolicyInstructions(policy Policy) string {
	var builder strings.Builder
	builder.WriteString("\n\nEffective recipient-owned runtime policy:\n- Mode: ")
	builder.WriteString(string(policy.Mode))
	if !policy.AllowWrites {
		builder.WriteString("\n- Do not write or modify files.")
	}
	if !policy.AllowShell {
		builder.WriteString("\n- Do not invoke a shell or execute commands.")
	}
	if !policy.AllowNetwork {
		builder.WriteString("\n- Do not access the network.")
	}
	if !policy.AllowMCPs {
		builder.WriteString("\n- Do not invoke MCP tools.")
	}
	if len(policy.DeniedCommands) > 0 {
		builder.WriteString("\n- Never run commands matching these locally denied prefixes: ")
		builder.WriteString(strings.Join(policy.DeniedCommands, ", "))
	}
	return builder.String()
}

// ConstrainRequest applies the already-computed effective policy to local path
// grants. A peer asking for a writable workspace or deliverable directory does
// not turn a read-only receiver into a writer.
func ConstrainRequest(request RunRequest, policy Policy) RunRequest {
	request.Workspaces = append([]Workspace(nil), request.Workspaces...)
	if !policy.AllowWrites {
		for index := range request.Workspaces {
			request.Workspaces[index].Mode = WorkspaceReadOnly
		}
		request.ReturnDirectory = ""
	}
	return request
}
