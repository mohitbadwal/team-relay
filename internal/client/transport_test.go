package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestClientPrivateLANHTTPPolicy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		url     string
		allowed bool
	}{
		{"http://192.168.1.4:8080", true}, {"http://10.0.0.1", true},
		{"http://172.16.0.1", true}, {"http://172.31.255.254", true},
		{"http://[fc00::1]", true}, {"http://[fdff::1]", true},
		{"http://[::ffff:192.168.1.4]", true},
		{"http://LOCALHOST", true}, {"http://127.0.0.2", true},
		{"https://relay.example", true},
		{"http://172.15.255.255", false}, {"http://172.32.0.1", false},
		{"http://192.169.0.1", false}, {"http://169.254.1.2", false},
		{"http://100.64.0.1", false}, {"http://0.0.0.0", false},
		{"http://224.0.0.1", false}, {"http://[fe80::1]", false},
		{"http://[::]", false}, {"http://[::ffff:8.8.8.8]", false},
		{"http://relay.local", false}, {"http://192.168.1.4.nip.io", false},
		{"http://localhost.evil", false}, {"http://localhost.", false},
		{"http://127.1", false}, {"http://2130706433", false},
		{"http://user:secret@192.168.1.4", false},
		{"http://192.168.1.4?token=secret", false}, {"http://192.168.1.4?", false},
		{"http://192.168.1.4#fragment", false}, {"http://192.168.1.4#", false},
		{"https://:8080", false}, {"ftp://192.168.1.4", false},
	} {
		t.Run(test.url, func(t *testing.T) {
			_, err := New(test.url, "fixture-token", nil)
			if (err == nil) != test.allowed {
				t.Errorf("New(%q) error = %v; allowed=%t", test.url, err, test.allowed)
			}
		})
	}
}

func TestClientDoesNotInheritAdminHTTPHostnameException(t *testing.T) {
	t.Setenv("TEAM_RELAY_ALLOW_HTTP_HOST", "relay.example")
	if _, err := New("http://relay.example", "fixture-token", nil); err == nil {
		t.Fatal("requester/receiver inherited admin-only HTTP exception")
	}
	if _, err := New("http://relay.example", "fixture-token", nil); err == nil || !strings.Contains(err.Error(), "private LAN IPs") {
		t.Fatalf("public HTTP error did not explain accepted private LAN addresses: %v", err)
	}
}

func TestLANClientUsesLiteralHostAndStillRejectsRedirects(t *testing.T) {
	t.Parallel()
	calls := 0
	httpClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Host != "192.168.1.4:8080" || request.URL.Path != "/relay/v1/agents" {
			t.Errorf("unexpected LAN request target: %s", request.URL)
		}
		if request.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("LAN request lost authentication")
		}
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": []string{"http://192.168.1.5:8080/capture"}},
			Body:       io.NopCloser(strings.NewReader("redirect")), Request: request,
		}, nil
	})}
	relay, err := New("http://192.168.1.4:8080/relay", "fixture-token", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.ListAgents(context.Background(), AgentQuery{}); err == nil {
		t.Fatal("redirect was treated as a successful LAN response")
	}
	if calls != 1 {
		t.Fatalf("LAN client followed a redirect (%d requests)", calls)
	}
}
