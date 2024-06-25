package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "No Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: http.Header{
				"Authorization": []string{"InvalidHeader"},
			},
			expectedKey: "",
			expectedErr: ErrMalformedAuthHeader,
		},
		{
			name: "Incorrect Authorization Scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer somekey"},
			},
			expectedKey: "",
			expectedErr: ErrMalformedAuthHeader,
		},
		{
			name: "Correct Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey somekey"},
			},
			expectedKey: "somekey",
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if key != tt.expectedKey {
				t.Errorf("expected key |%v|, got |%v|", tt.expectedKey, key)
			}
			if err != tt.expectedErr {
				t.Errorf("expected |%v|, got |%v|", tt.expectedErr, err)
			}
		})
	}
}
