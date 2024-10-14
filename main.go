package main

import (
	"fmt"
	"net/http"
	"time"
)

type Login struct {
	HashedPass   string
	SessionToken string
	CSRFToken    string
}

var users = map[string]Login{}

func main() {
	fmt.Println("Server starting on port 8080...")
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.ListenAndServe(":8080", nil)
}

func register(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Request received at /register")
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid Method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(username) < 6 || len(password) < 8 {
		fmt.Println("Something wrong with username/password")
		er := http.StatusNotAcceptable
		http.Error(w, "Invalid username or password", er)
		return
	}

	if _, ok := users[username]; ok {
		er := http.StatusConflict
		http.Error(w, "Username already exists", er)
		return
	}

	hashedPasword, _ := hashPassword(password)
	fmt.Println("password hashed")
	users[username] = Login{
		HashedPass: hashedPasword,
	}

	fmt.Fprint(w, "User registered succesfully!")
}

func login(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Request received at /login")
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid Method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]

	if !ok || !checkPassword(password, user.HashedPass) {
		er := http.StatusUnauthorized
		http.Error(w, "Invalid password or username", er)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(2 * time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(2 * time.Hour),
		HttpOnly: false,
	})

	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user
	fmt.Fprint(w, "User logged in succesfully!")
}

func protected(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Request received at /protected")
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid Method", er)
		return
	}

	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}

	username := r.FormValue("username")

	fmt.Fprintf(w, "CSRF validation success! Welcome, %s", username)

}

func logout(w http.ResponseWriter, r *http.Request) {
	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthroized", er)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	username := r.FormValue("username")
	user, _ := users[username]
	user.SessionToken = ""
	user.CSRFToken = ""
	users[username] = user

	fmt.Fprintln(w, "Logged out..")

}
