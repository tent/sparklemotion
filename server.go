package main

import (
	"html/template"
	"mime/multipart"
	"log"
	"net/http"
	"os"
	"regexp"
)

var indexTemplate = template.Must(template.ParseFiles("templates/_layout.html", "templates/index.html"))

var indexHandler = func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	err := indexTemplate.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

var (
	versionPattern   = regexp.MustCompile(`[0-9]\.[0-9]\w*`)
	signaturePattern = regexp.MustCompile(`[A-Za-z0-9/+]+=*`)
)

var pushHandler = func(w http.ResponseWriter, r *http.Request) {
	channel := r.FormValue("channel")
	if channel != "alpha" && channel != "beta" && channel != "stable" {
		http.Error(w, "Invalid release channel", http.StatusBadRequest)
		return
	}
	if !versionPattern.MatchString(r.FormValue("version")) {
		http.Error(w, "Invalid version number", http.StatusBadRequest)
		return
	}
	if r.FormValue("title") == "" {
		http.Error(w, "Missing title", http.StatusBadRequest)
		return
	}
	signature := r.FormValue("signature")
	if signature != "" && !signaturePattern.MatchString(signature) {
		http.Error(w, "Invalid DSA signature", http.StatusBadRequest)
	}
	_, _, err := r.FormFile("file")
	if err == http.ErrMissingFile {
		http.Error(w, "Missing file", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func uploadFile(f multipart.File, fh *multipart.FileHeader, version string) error {
	return nil
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/push", pushHandler)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func init() {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		log.Fatal("Missing AWS_ACCESS_KEY_ID environment variable")
		os.Exit(1)
	}
	if os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		log.Fatal("Missing AWS_SECRET_ACCESS_KEY environment variable")
		os.Exit(1)
	}
}
