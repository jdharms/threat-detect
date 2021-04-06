package auth

import (
	"context"
	"crypto/subtle"
	"net/http"
)

type ValidationFunc func(username, password string) bool

type AuthorizationCtx string

func NewBasicAuth(validator ValidationFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()

			if !ok || !validator(username, password) {
				http.Error(w, "authorization failed", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), AuthorizationCtx("authorizedUser"), username)

			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func NewMapValidator(credentials map[string]string) ValidationFunc {
	return func(username, password string) bool {

		// ensure username is in credentials map
		if pw, ok := credentials[username]; !ok {
			return false
		} else { // ensure password matches expected
			return subtle.ConstantTimeCompare([]byte(password), []byte(pw)) == 1
		}
	}
}
