package main

import (
	"errors"
	"net/http"
)

var AuthErr = errors.New("Unauthorized")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]

	if !ok {
		return AuthErr
	}

	st, err := r.Cookie("session_token")

	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return AuthErr
	}

	csrf := r.Header.Get("X-CSRF-Token")

	if csrf != user.CSRFToken || csrf == "" {
		return AuthErr
	}

	return nil
}
