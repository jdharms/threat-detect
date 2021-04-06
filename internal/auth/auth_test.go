package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBasicAuth(t *testing.T) {
	var innerHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.Context().Value(AuthorizationCtx("authorizedUser"))
		if val == nil {
			t.Errorf("authorizedUser tag not added to request context")
		}
	})

	testCases := []struct {
		name         string
		sut          http.Handler
		expectedCode int
		testUser     string
		testPass     string
	}{
		{
			"auth success",
			NewBasicAuth(func(string, string) bool { return true })(innerHandler),
			200,
			"username",
			"password",
		},
		{
			"auth fail",
			NewBasicAuth(func(string, string) bool { return false })(innerHandler),
			401,
			"username",
			"password",
		},
		{
			"auth missing",
			NewBasicAuth(func(string, string) bool { return true })(innerHandler), // test should NOT call validator at all
			401,
			"",
			"",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {

			req, err := http.NewRequest("POST", "http://testing.com", nil)
			if err != nil {
				t.Errorf("http.NewRequest returned an error: %w", err)
			}
			if test.testPass != "" {
				req.SetBasicAuth(test.testUser, test.testPass)
			}

			recorder := httptest.NewRecorder()
			test.sut.ServeHTTP(recorder, req)
			if test.expectedCode != recorder.Code {
				t.Errorf("expected status code %d but got %d", test.expectedCode, recorder.Code)
			}
		})
	}
}

func TestMapValidator(t *testing.T) {
	testCases := []struct {
		name     string
		creds    map[string]string
		user     string
		pwd      string
		expected bool
	}{
		{
			"false when absent",
			map[string]string{"user": "pass"},
			"someOtherUser",
			"doesn'tmatter",
			false,
		},
		{
			"false when not matching",
			map[string]string{"user": "pass"},
			"user",
			"someOtherPass",
			false,
		},
		{
			"true when matching",
			map[string]string{"user": "pass", "anotherUser": "anotherPass"},
			"user",
			"pass",
			true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			v := NewMapValidator(test.creds)
			if v(test.user, test.pwd) != test.expected {
				t.Error("validator returned unexpected result")
			}
		})
	}
}
