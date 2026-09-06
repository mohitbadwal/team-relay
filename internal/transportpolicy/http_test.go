package transportpolicy

import (
	"bytes"
	"strings"
	"testing"
)

func TestPlainHTTPAllowedHasExactPrivateRanges(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		host    string
		allowed bool
		lan     bool
	}{
		{"localhost", true, false}, {"LOCALHOST", true, false},
		{"127.0.0.1", true, false}, {"127.23.45.67", true, false},
		{"127.0.0.0", true, false}, {"127.255.255.255", true, false},
		{"::1", true, false}, {"::ffff:127.0.0.1", true, false},
		{"9.255.255.255", false, false}, {"10.0.0.0", true, true},
		{"10.255.255.255", true, true}, {"11.0.0.0", false, false},
		{"172.15.255.255", false, false}, {"172.16.0.0", true, true},
		{"172.31.255.255", true, true}, {"172.32.0.0", false, false},
		{"192.167.255.255", false, false}, {"192.168.0.0", true, true},
		{"192.168.1.4", true, true}, {"192.168.255.255", true, true},
		{"192.169.0.0", false, false},
		{"fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false, false},
		{"fc00::", true, true}, {"fd00::1", true, true},
		{"FDFF:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, true},
		{"fe00::", false, false}, {"fe80::1", false, false},
		{"fec0::1", false, false}, {"ff02::1", false, false},
		{"::", false, false}, {"2001:4860:4860::8888", false, false},
		{"::ffff:10.1.2.3", true, true}, {"::ffff:172.16.1.2", true, true},
		{"::FFFF:C0A8:0104", true, true}, {"::ffff:8.8.8.8", false, false},
		{"::ffff:169.254.1.2", false, false}, {"::ffff:100.64.0.1", false, false},
		{"::ffff:0.0.0.0", false, false}, {"::ffff:224.0.0.1", false, false},
		{"::ffff:0:192.168.1.4", false, false},
		{"0.0.0.0", false, false}, {"8.8.8.8", false, false},
		{"169.254.1.2", false, false}, {"100.64.0.0", false, false},
		{"100.127.255.255", false, false}, {"224.0.0.1", false, false},
		{"255.255.255.255", false, false}, {"192.0.2.1", false, false},
		{"relay.local", false, false}, {"relay", false, false},
		{"localhost.example", false, false}, {"localhost.", false, false},
		{"192.168.1.4.example", false, false}, {"10.0.0.1.nip.io", false, false},
		{"fd00::1%en0", false, false}, {"fe80::1%en0", false, false},
		{"127.1", false, false}, {"2130706433", false, false},
		{"0x7f000001", false, false}, {"010.0.0.1", false, false},
		{"[fd00::1]", false, false}, {"192.168.1.4:8080", false, false},
		{" localhost", false, false}, {"localhost ", false, false}, {"", false, false},
	} {
		t.Run(test.host, func(t *testing.T) {
			if got := PlainHTTPAllowed(test.host); got != test.allowed {
				t.Errorf("PlainHTTPAllowed(%q) = %t; want %t", test.host, got, test.allowed)
			}
			if got := PrivateLANHost(test.host); got != test.lan {
				t.Errorf("PrivateLANHost(%q) = %t; want %t", test.host, got, test.lan)
			}
		})
	}
}

func TestPrivateLANWarningIsFixedAndOnlyForCleartextLAN(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		url  string
		warn bool
	}{
		{"http://192.168.1.4:8080", true},
		{"http://[fd00::1]:8080", true},
		{"http://[::ffff:192.168.1.4]:8080", true},
		{"http://secret:password@10.1.2.3/private-path", true},
		{"https://192.168.1.4:8080", false},
		{"http://LOCALHOST:8080", false}, {"http://127.0.0.1:8080", false},
		{"http://[::1]:8080", false}, {"http://relay", false},
		{"http://8.8.8.8", false}, {"http://%", false},
	} {
		var output bytes.Buffer
		WarnPrivateLANHTTP(test.url, &output)
		if test.warn {
			if output.String() != PrivateLANWarning+"\n" {
				t.Errorf("warning for %q = %q", test.url, output.String())
			}
			for _, required := range []string{"unencrypted", "credentials", "trusted-LAN testing", "HTTPS"} {
				if !strings.Contains(output.String(), required) {
					t.Errorf("warning lacks %q", required)
				}
			}
		} else if output.Len() != 0 {
			t.Errorf("unexpected warning for %q: %s", test.url, output.String())
		}
	}
}
