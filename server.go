// +build ignore

package main

import (
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Poisoned!")
}

func main() {
	fmt.Println("Server started on 0.0.0.0:80")
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":80", nil))
}
