package lifecycle

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
)

func TestConfigLiteralParsingAndValidation(t *testing.T) {
	values, err := parseConfig("# configuration\nTEAM_RELAY_SERVER_MODE=native\nTEAM_RELAY_RECEIVER_CONFIG=folder with spaces/config.yaml\nTEAM_RELAY_REDIS_URL=redis://user:$(touch pwned)@localhost/0\n")
	if err != nil {
		t.Fatal(err)
	}
	if values["TEAM_RELAY_RECEIVER_CONFIG"] != "folder with spaces/config.yaml" || values["TEAM_RELAY_REDIS_URL"] != "redis://user:$(touch pwned)@localhost/0" {
		t.Fatal("configuration was interpreted instead of read literally")
	}
	for _, invalid := range []string{
		"export TEAM_RELAY_SERVER_MODE=native", "unknown=super-secret",
		"TEAM_RELAY_PORT=1\nTEAM_RELAY_PORT=2", "TEAM_RELAY_PORT=\x00super-secret",
		"TEAM_RELAY_SERVER_MODE =native", "rm -rf anything",
	} {
		_, err := parseConfig(invalid)
		if err == nil {
			t.Errorf("accepted invalid configuration %q", invalid)
		} else if strings.Contains(err.Error(), "super-secret") {
			t.Error("config error disclosed a value")
		}
	}
}

func TestServiceIdentityIsScopedByRoleAndAbsoluteConfigPath(t *testing.T) {
	base := t.TempDir()
	first := serviceID("server", filepath.Join(base, "one.conf"))
	if first == serviceID("receiver", filepath.Join(base, "one.conf")) || first == serviceID("server", filepath.Join(base, "two.conf")) {
		t.Fatal("different roles or configurations share a service ID")
	}
	if first != serviceID("server", filepath.Join(base, "sub", "..", "one.conf")) {
		t.Fatal("equivalent absolute paths have different service IDs")
	}
	if strings.ContainsAny(first, "/\\ \n") {
		t.Fatal("service ID is unsafe for service-manager names")
	}
}

func TestSpecResolvesRelativePathsAndKeepsEnvironmentNarrow(t *testing.T) {
	base := t.TempDir()
	cfg := configuration{filepath.Join(base, "team-relay.conf"), map[string]string{
		"TEAM_RELAY_REDIS_URL":    "redis://user:private-value@127.0.0.1:6379/0",
		"TEAM_RELAY_BIND_ADDRESS": "0.0.0.0", "TEAM_RELAY_PORT": "9876",
		"TEAM_RELAY_RECEIVER_CONFIG":    "receiver/config.yaml",
		"TEAM_RELAY_RECEIVER_STATE_DIR": "receiver/state",
	}}
	server, err := makeSpec(cfg, "server", "/a/home", "/a/tool/path")
	if err != nil {
		t.Fatal(err)
	}
	if server.executable != filepath.Join(base, "bin", "team-relay-server") || server.environment["TEAM_RELAY_BOOTSTRAP_TOKEN_FILE"] != filepath.Join(base, "secrets", "bootstrap-token") {
		t.Fatal("server paths did not resolve relative to config")
	}
	if len(server.environment) != 3 || server.environment["TEAM_RELAY_ADDR"] != "0.0.0.0:9876" {
		t.Fatalf("unexpected server environment keys: %v", sortedKeys(server.environment))
	}
	receiver, err := makeSpec(cfg, "receiver", "/a/home", "/a/tool/path")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--config", filepath.Join(base, "receiver", "config.yaml"), "--state-dir", filepath.Join(base, "receiver", "state"), "--control-address", "127.0.0.1:8787", "run"}
	if !reflect.DeepEqual(receiver.args, want) {
		t.Fatalf("receiver arguments: %v", receiver.args)
	}
	if !reflect.DeepEqual(receiver.environment, map[string]string{"HOME": "/a/home", "PATH": "/a/tool/path"}) {
		t.Fatal("receiver service captured unexpected environment")
	}
}

func TestSpecRejectsUnsafeSettingsWithoutEchoingValues(t *testing.T) {
	for _, test := range []struct{ key, value, role string }{
		{"TEAM_RELAY_BIND_ADDRESS", "some-secret", "server"},
		{"TEAM_RELAY_PORT", "0", "server"},
		{"TEAM_RELAY_PORT", "65536", "server"},
		{"TEAM_RELAY_REDIS_URL", "some-secret", "server"},
		{"TEAM_RELAY_RECEIVER_CONTROL_ADDRESS", "0.0.0.0:8787", "receiver"},
		{"TEAM_RELAY_RECEIVER_CONTROL_ADDRESS", "localhost:0", "receiver"},
	} {
		cfg := configuration{filepath.Join(t.TempDir(), "team-relay.conf"), map[string]string{test.key: test.value}}
		_, err := makeSpec(cfg, test.role, "/home", "/bin")
		if err == nil {
			t.Errorf("accepted invalid %s", test.key)
		} else if strings.Contains(err.Error(), "some-secret") {
			t.Fatal("validation disclosed a config value")
		}
	}
}

func TestServiceDefinitionsQuoteWithoutShellEvaluation(t *testing.T) {
	spec := serviceSpec{
		id: "com.team-relay.receiver.test", role: "receiver",
		executable: "/tmp/a space/$USER%h/agent", workingDir: "/tmp/a space/%h",
		args:        []string{"--config", "/tmp/config\"&<$X%h\\.yaml", "run"},
		environment: map[string]string{"PATH": "/tmp/$TOOLS:%h", "HOME": "/tmp/quoted\"home"},
	}
	unit := string(systemdUnit(spec))
	for _, expected := range []string{`"/tmp/a space/$$USER%%h/agent"`, `WorkingDirectory="/tmp/a space/%%h"`, `Environment="PATH=/tmp/$TOOLS:%%h"`, `Restart=always`, `UMask=0077`} {
		if !strings.Contains(unit, expected) {
			t.Errorf("systemd definition lacks escaped value %q", expected)
		}
	}
	if strings.Contains(unit, "/bin/sh") || strings.Contains(unit, "bash -c") {
		t.Fatal("service definition invokes a shell")
	}
	plist := launchAgent(spec, "/tmp/log&file")
	decoder := xml.NewDecoder(bytes.NewReader(plist))
	var stringsFound []string
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("invalid launchd XML: %v", err)
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "string" {
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				t.Fatal(err)
			}
			stringsFound = append(stringsFound, value)
		}
	}
	for _, expected := range append([]string{spec.executable, spec.workingDir, "/tmp/log&file"}, spec.args...) {
		found := false
		for _, value := range stringsFound {
			found = found || value == expected
		}
		if !found {
			t.Errorf("launchd plist changed literal argument %q", expected)
		}
	}
}

type fakeExecutor struct {
	calls     []string
	outputs   map[string]string
	fail      map[string]bool
	sequences map[string][]fakeOutput
}

type fakeOutput struct {
	text string
	fail bool
}

func (f *fakeExecutor) output(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, key)
	if sequence := f.sequences[key]; len(sequence) > 0 {
		result := sequence[0]
		f.sequences[key] = sequence[1:]
		if result.fail {
			return []byte(result.text), errors.New("service manager rejected command")
		}
		return []byte(result.text), nil
	}
	if f.fail[key] {
		return []byte(f.outputs[key]), errors.New("service manager rejected command")
	}
	return []byte(f.outputs[key]), nil
}

func (f *fakeExecutor) stream(ctx context.Context, _ io.Writer, _ io.Writer, name string, args ...string) error {
	_, err := f.output(ctx, name, args...)
	return err
}

func fixture(t *testing.T, platform string) (manager, string, *fakeExecutor) {
	t.Helper()
	base := filepath.Join(t.TempDir(), "private")
	if err := privatefs.EnsureDirectory(base); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "team-relay.conf")
	if err := privatefs.WriteNewFile(path, []byte("TEAM_RELAY_SERVER_MODE=native\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	commands := &fakeExecutor{outputs: map[string]string{}, fail: map[string]bool{}}
	m := manager{platform: platform, home: filepath.Join(base, "home"), configBase: filepath.Join(base, "config"), uid: "12345", path: "/usr/bin:/bin", commands: commands,
		pause: func(context.Context, time.Duration) error { return nil },
	}
	return m, path, commands
}

func notFound(m manager, commands *fakeExecutor, role, configPath string) {
	id := serviceID(role, configPath)
	if m.platform == "darwin" {
		key := "launchctl print gui/" + m.uid + "/" + id
		commands.outputs[key], commands.fail[key] = "Could not find service", true
	} else {
		key := "systemctl --user show " + id + ".service --property=LoadState,ActiveState,SubState,MainPID,ExecMainStatus --no-pager"
		commands.outputs[key] = "LoadState=not-found\nActiveState=inactive\n"
	}
}

func TestInvalidRequestsNeverExecuteCommands(t *testing.T) {
	m, path, commands := fixture(t, "linux")
	for _, test := range []struct {
		role, action string
		follow       bool
	}{
		{"other", "start", false}, {"server", "delete", false}, {"server", "stop", true},
	} {
		if err := m.run(context.Background(), test.role, test.action, path, test.follow, io.Discard, io.Discard); err == nil {
			t.Fatal("invalid lifecycle request was accepted")
		}
	}
	if len(commands.calls) != 0 {
		t.Fatal("invalid request executed commands")
	}
}

func TestNativeUnsupportedPlatformIsClearAndDoesNotExecute(t *testing.T) {
	m, path, commands := fixture(t, "windows")
	err := m.run(context.Background(), "server", "start", path, false, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "unsupported on windows") || len(commands.calls) != 0 {
		t.Fatalf("unexpected unsupported-platform result: %v", err)
	}
}

func TestStatusAndStopWorkWhenRuntimeFilesAreMissing(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			m, path, commands := fixture(t, platform)
			notFound(m, commands, "receiver", path)
			for _, action := range []string{"status", "stop"} {
				var out bytes.Buffer
				if err := m.run(context.Background(), "receiver", action, path, false, &out, io.Discard); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), "stopped") {
					t.Fatalf("unexpected output %q", out.String())
				}
			}
			for _, call := range commands.calls {
				if strings.Contains(call, "bootstrap") || strings.Contains(call, " start ") || strings.Contains(call, "disable") || strings.Contains(call, "bootout") {
					t.Fatalf("stopped service caused an unsafe mutation: %s", call)
				}
			}
		})
	}
}

func TestStatusRedactsLaunchctlEnvironmentAndStartIsIdempotent(t *testing.T) {
	m, path, commands := fixture(t, "darwin")
	id := serviceID("server", path)
	commands.outputs["launchctl print gui/"+m.uid+"/"+id] = "state = running\n pid = 123\n environment = {\n REDIS_URL = redis://private-credential@host\n }\n"
	var out bytes.Buffer
	for _, action := range []string{"status", "start"} {
		if err := m.run(context.Background(), "server", action, path, false, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(out.String(), "private-credential") || !strings.Contains(out.String(), "pid=123") || !strings.Contains(out.String(), "already running") {
		t.Fatalf("incorrect status/start output: %s", out.String())
	}
	for _, call := range commands.calls {
		if !strings.HasPrefix(call, "launchctl print ") {
			t.Fatalf("idempotent start mutated service: %s", call)
		}
	}
}

func TestDefinitionAndLogPrivacyAndForeignEntryProtection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native service-manager symlinks are only installed on Unix")
	}
	m, path, _ := fixture(t, "darwin")
	spec := serviceSpec{id: serviceID("server", path), role: "server", executable: "/safe/server", workingDir: filepath.Dir(path), environment: map[string]string{"REDIS_URL": "redis://private-credential@localhost/0"}}
	layout := layoutFor(m.platform, m.home, m.configBase, spec.id)
	if err := installDefinition(m.platform, spec, layout); err != nil {
		t.Fatal(err)
	}
	for _, privatePath := range []string{layout.unit, layout.log} {
		info, err := os.Lstat(privatePath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private mode missing on %s: %v", privatePath, err)
		}
	}
	if target, err := os.Readlink(layout.entry); err != nil || target != layout.unit {
		t.Fatal("service entry does not link to this scoped definition")
	}
	if err := installDefinition(m.platform, spec, layout); err != nil {
		t.Fatalf("idempotent definition installation failed: %v", err)
	}
	if err := os.Remove(layout.entry); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/another/service.plist", layout.entry); err != nil {
		t.Fatal(err)
	}
	if err := installDefinition(m.platform, spec, layout); err == nil {
		t.Fatal("foreign service-manager entry was accepted")
	}
	if err := removeEntry(layout); err == nil {
		t.Fatal("foreign service-manager entry could be removed")
	}
}

func TestDockerDelegationUsesScriptWithoutNativeValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Docker shell wrapper runs on Unix/WSL")
	}
	m, path, commands := fixture(t, "darwin")
	if err := privatefs.AtomicWriteFile(path, []byte("TEAM_RELAY_SERVER_MODE=docker\nTEAM_RELAY_PORT=0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(filepath.Dir(path), "team-relay")
	if err := privatefs.WriteNewFile(wrapper, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := m.run(context.Background(), "server", "logs", path, true, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%s server logs --config %s --follow", wrapper, path)
	if !reflect.DeepEqual(commands.calls, []string{want}) {
		t.Fatalf("unexpected Docker delegation: %v", commands.calls)
	}
}

func serverInputs(t *testing.T, configPath string) {
	t.Helper()
	base := filepath.Dir(configPath)
	for _, dir := range []string{"bin", "secrets"} {
		if err := privatefs.EnsureDirectory(filepath.Join(base, dir)); err != nil {
			t.Fatal(err)
		}
	}
	if err := privatefs.WriteNewFile(filepath.Join(base, "bin", "team-relay-server"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := privatefs.WriteNewFile(filepath.Join(base, "secrets", "bootstrap-token"), []byte("private-fixture-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNativeStartAndRestartReloadScopedDefinition(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native service installation requires Unix executable and symlink semantics")
	}
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			m, path, commands := fixture(t, platform)
			serverInputs(t, path)
			notFound(m, commands, "server", path)
			if err := m.run(context.Background(), "server", "start", path, false, io.Discard, io.Discard); err != nil {
				t.Fatal(err)
			}
			id := serviceID("server", path)
			layout := layoutFor(platform, m.home, m.configBase, id)
			if err := privatefs.AtomicWriteFile(path, []byte("TEAM_RELAY_SERVER_MODE=native\nTEAM_RELAY_PORT=9876\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if platform == "darwin" {
				key := "launchctl print gui/" + m.uid + "/" + id
				commands.sequences = map[string][]fakeOutput{key: {
					{text: "state = running\npid = 123\n"},
					{text: "state = terminating\npid = 123\n"},
					{text: "Could not find service", fail: true},
					{text: "Could not find service", fail: true},
				}}
			} else {
				key := "systemctl --user show " + id + ".service --property=LoadState,ActiveState,SubState,MainPID,ExecMainStatus --no-pager"
				commands.outputs[key] = "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nExecMainStatus=0\n"
			}
			commands.calls = nil
			if err := m.run(context.Background(), "server", "restart", path, false, io.Discard, io.Discard); err != nil {
				t.Fatal(err)
			}
			payload, err := privatefs.ReadFile(layout.unit)
			if err != nil || !bytes.Contains(payload, []byte("127.0.0.1:9876")) {
				t.Fatalf("restart did not reload config: %v", err)
			}
			wantLast := "systemctl --user restart " + id + ".service"
			if platform == "darwin" {
				wantLast = "launchctl bootstrap gui/" + m.uid + " " + layout.entry
			}
			if commands.calls[len(commands.calls)-1] != wantLast {
				t.Fatalf("restart did not target scoped service: %v", commands.calls)
			}
			if platform == "darwin" {
				key := "launchctl print gui/" + m.uid + "/" + id
				if len(commands.sequences[key]) != 0 {
					t.Fatal("bootstrap ran before scoped deregistration was confirmed")
				}
			}
		})
	}
}

func TestFailedActivationLeavesPrivateLogsInspectableAndRedactsManagerOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native service installation requires Unix executable and symlink semantics")
	}
	m, path, commands := fixture(t, "darwin")
	serverInputs(t, path)
	notFound(m, commands, "server", path)
	id := serviceID("server", path)
	layout := layoutFor(m.platform, m.home, m.configBase, id)
	bootstrap := "launchctl bootstrap gui/" + m.uid + " " + layout.entry
	commands.fail[bootstrap], commands.outputs[bootstrap] = true, "some-secret environment content"
	err := m.run(context.Background(), "server", "start", path, false, io.Discard, io.Discard)
	if err == nil || strings.Contains(err.Error(), "some-secret") {
		t.Fatalf("incorrect failed activation error: %v", err)
	}
	if err := privatefs.ValidateRegularFile(layout.log); err != nil {
		t.Fatalf("failed start did not leave a private log: %v", err)
	}
	if err := m.run(context.Background(), "server", "logs", path, true, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if last := commands.calls[len(commands.calls)-1]; last != "tail -n 100 -F "+layout.log {
		t.Fatalf("logs targeted a different service: %s", last)
	}
	if err := m.run(context.Background(), "server", "stop", path, false, io.Discard, io.Discard); err != nil {
		t.Fatalf("failed-start entry could not be stopped: %v", err)
	}
	if _, err := os.Lstat(layout.entry); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stop did not remove the failed-start login entry")
	}
}

func TestConfigFileMustRemainPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows privacy is enforced through ACLs, not Unix mode changes")
	}
	m, path, commands := fixture(t, "linux")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.run(context.Background(), "server", "start", path, false, io.Discard, io.Discard); err == nil || len(commands.calls) != 0 {
		t.Fatal("non-private lifecycle config reached the service manager")
	}
}

func TestReceiverServiceInheritsOnlySelectedProfileAllowlist(t *testing.T) {
	_, configPath, _ := fixture(t, "linux")
	receiverPath := filepath.Join(filepath.Dir(configPath), "receiver.yaml")
	payload := `version: 1
relay:
  url: https://relay.example.invalid
receiver:
  profile: selected
profiles:
  selected:
    runtime: external
    environment_allowlist:
      - LIFECYCLE_ALLOWED
      - LIFECYCLE_UNSET
      - TEAM_RELAY_DEVICE_TOKEN
      - team_relay_admin_token
  inactive:
    runtime: external
    environment_allowlist:
      - LIFECYCLE_OTHER_PROFILE
`
	if err := privatefs.WriteNewFile(receiverPath, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := serviceSpec{role: "receiver", args: []string{"--config", receiverPath}, environment: map[string]string{"HOME": "/the/home", "PATH": "/the/path"}}
	environment := []string{
		"LIFECYCLE_ALLOWED=private-provider-key-$literal%value",
		"LIFECYCLE_UNLISTED=must-not-persist",
		"LIFECYCLE_OTHER_PROFILE=must-not-persist",
		"TEAM_RELAY_DEVICE_TOKEN=tr_dev_must-not-persist",
		"team_relay_admin_token=tr_admin_must-not-persist",
		"HTTPS_PROXY=unlisted-operational-value",
	}
	if err := inheritReceiverEnvironment(&spec, environment); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"HOME": "/the/home", "PATH": "/the/path", "LIFECYCLE_ALLOWED": "private-provider-key-$literal%value"}
	if !reflect.DeepEqual(spec.environment, want) {
		t.Fatalf("unexpected service environment names: %v", sortedKeys(spec.environment))
	}
	for _, rendered := range [][]byte{systemdUnit(spec), launchAgent(spec, "/tmp/log")} {
		if bytes.Contains(rendered, []byte("must-not-persist")) || bytes.Contains(rendered, []byte("unlisted-operational-value")) {
			t.Fatal("generated service definition leaked an unlisted or relay authority variable")
		}
		if !bytes.Contains(rendered, []byte("LIFECYCLE_ALLOWED")) {
			t.Fatal("generated service definition omitted the selected allowed variable")
		}
	}
	if err := inheritReceiverEnvironment(&spec, []string{"LIFECYCLE_ALLOWED=secret\nsecond-line"}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("invalid environment value was accepted or disclosed")
	}
}

func TestLaunchctlDeregistrationWaitIsBoundedAndDoesNotRetryManagerErrors(t *testing.T) {
	m, path, commands := fixture(t, "darwin")
	id := serviceID("server", path)
	key := "launchctl print gui/" + m.uid + "/" + id
	commands.outputs[key] = "state = terminating\n"
	pauses := 0
	m.pause = func(context.Context, time.Duration) error { pauses++; return nil }
	err := m.unloadLaunchAgent(context.Background(), id)
	if err == nil || !strings.Contains(err.Error(), "within 15 seconds") || pauses != 59 {
		t.Fatalf("deregistration timeout was not bounded: pauses=%d, error=%v", pauses, err)
	}
	if len(commands.calls) != 61 { // one bootout and sixty scoped inspections
		t.Fatalf("unexpected timeout command count: %d", len(commands.calls))
	}
	for _, call := range commands.calls {
		if strings.Contains(call, "bootstrap") || !strings.Contains(call, id) {
			t.Fatalf("deregistration wait touched a different service: %s", call)
		}
	}
	commands.calls, pauses = nil, 0
	commands.fail[key], commands.outputs[key] = true, "Permission denied"
	err = m.unloadLaunchAgent(context.Background(), id)
	if err == nil || pauses != 0 || len(commands.calls) != 2 {
		t.Fatalf("manager error was retried: calls=%d pauses=%d error=%v", len(commands.calls), pauses, err)
	}
}
