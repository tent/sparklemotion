package main

import (
	"html/template"
	"log"
	"net/http"
)

var indexTemplate = template.Must(template.ParseFiles("templates/_layout.html", "templates/index.html"))

var indexHandler = func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	err := indexTemplate.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/", indexHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
