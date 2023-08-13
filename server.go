package main

import (
	"log"
	"net/http"
)

func serve() {
	http.HandleFunc("/login", githubLoginHandler)
	http.HandleFunc("/login/callback", githubCallbackHandler)
	http.HandleFunc("/whoami", unauthorizedUserHandler)

	log.Println("Server listening on port 3000")
	http.ListenAndServe("0.0.0.0:3000", nil)
}
