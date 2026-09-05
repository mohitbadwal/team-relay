package main

import "testing"

func TestRecipientRunMarkerFailsClosedOnlyForTrustedValue(t *testing.T) {
	for _, testCase := range []struct {
		value string
		want  bool
	}{
		{value: "", want: false},
		{value: "0", want: false},
		{value: "true", want: false},
		{value: "1", want: true},
	} {
		if got := recipientRunBlocked(testCase.value); got != testCase.want {
			t.Fatalf("recipientRunBlocked(%q) = %t, want %t", testCase.value, got, testCase.want)
		}
	}
}
