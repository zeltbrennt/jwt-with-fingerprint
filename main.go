package main

import (
	"jwt-demo/routes"
	"log"
	"net/http"
)

func main() {
	http.Handle("/", http.FileServer(http.Dir("frontend/dist")))
	http.HandleFunc("/login", routes.Login)
	http.HandleFunc("/secret", routes.Secret)
	log.Println("staring Server")
	http.ListenAndServe(":8080", nil)
}
