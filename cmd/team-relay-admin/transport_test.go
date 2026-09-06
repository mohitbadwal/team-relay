package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/mohitbadwal/team-relay/internal/client"
)

func TestAdminAndDeviceClientAgreeOnLANHTTP(t *testing.T) {
	t.Setenv("TEAM_RELAY_ALLOW_HTTP_HOST", "")
	for _, test := range []struct {
		url     string
		allowed bool
	}{
		{"http://192.168.1.4:8080", true}, {"http://10.0.0.1", true},
		{"http://172.16.0.1", true}, {"http://172.31.255.254", true},
		{"http://[fc00::1]", true}, {"http://[fdff::1]", true},
		{"http://[::ffff:192.168.1.4]", true}, {"http://LOCALHOST", true},
		{"http://127.0.0.2", true}, {"http://[::1]", true},
		{"https://relay.example", true}, {"https://8.8.8.8", true},
		{"http://172.15.255.255", false}, {"http://172.32.0.0", false},
		{"http://192.169.0.1", false}, {"http://169.254.1.2", false},
		{"http://100.64.0.1", false}, {"http://0.0.0.0", false},
		{"http://224.0.0.1", false}, {"http://[fe80::1]", false},
		{"http://[::]", false}, {"http://[::ffff:8.8.8.8]", false},
		{"http://relay.local", false}, {"http://192.168.1.4.nip.io", false},
		{"http://user:secret@192.168.1.4", false},
		{"http://192.168.1.4?secret=x", false}, {"http://192.168.1.4?", false},
		{"http://192.168.1.4#fragment", false}, {"http://192.168.1.4#", false},
		{"https://user:secret@relay.example", false}, {"https://relay.example?x=1", false},
		{"https://:8080", false}, {"ftp://192.168.1.4", false},
	} {
		t.Run(test.url, func(t *testing.T) {
			_, adminErr := newAPIClient(test.url, "fixture-token")
			_, clientErr := client.New(test.url, "fixture-token", nil)
			if (adminErr == nil) != test.allowed || (clientErr == nil) != test.allowed {
				t.Errorf("URL=%q allowed=%t admin=%v client=%v", test.url, test.allowed, adminErr, clientErr)
			}
		})
	}
}

func TestAdminComposeHTTPExceptionRemainsExactAndAdminOnly(t *testing.T) {
	t.Setenv("TEAM_RELAY_ALLOW_HTTP_HOST", "relay")
	if _, err := newAPIClient("http://RELAY:8080", "fixture-token"); err != nil {
		t.Fatalf("exact case-insensitive Compose hostname was rejected: %v", err)
	}
	for _, denied := range []string{"http://relay.example", "http://relay.", "http://other", "http://8.8.8.8"} {
		if _, err := newAPIClient(denied, "fixture-token"); err == nil {
			t.Errorf("Compose hostname exception accepted %s", denied)
		}
	}
	if _, err := client.New("http://relay:8080", "fixture-token", nil); err == nil {
		t.Fatal("device client inherited admin Compose exception")
	}
	t.Setenv("TEAM_RELAY_ALLOW_HTTP_HOST", "*")
	if _, err := newAPIClient("http://arbitrary.example", "fixture-token"); err == nil {
		t.Fatal("admin hostname exception became a wildcard")
	}
}

type transportRoundTripper func(*http.Request) (*http.Response, error)

func (f transportRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestAdminLANClientNeverReplaysCredentialsToRedirect(t *testing.T) {
	t.Setenv("TEAM_RELAY_ALLOW_HTTP_HOST", "")
	admin, err := newAPIClient("http://192.168.1.4:8080", "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	admin.http.Transport = transportRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Host != "192.168.1.4:8080" || request.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("admin changed the request target or lost authentication")
		}
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": []string{"http://192.168.1.5:8080/capture"}},
			Body:       io.NopCloser(strings.NewReader("redirect")), Request: request,
		}, nil
	})
	if err := admin.request(http.MethodGet, "/v1/admin/members", nil, nil); err == nil {
		t.Fatal("redirect was treated as a successful admin response")
	}
	if calls != 1 {
		t.Fatalf("admin client followed a redirect (%d requests)", calls)
	}
}
