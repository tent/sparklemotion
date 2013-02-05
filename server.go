package main

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/russross/blackfriday"
	"github.com/titanous/go.xml"
	"github.com/titanous/sparklemotion/appcast"
	"launchpad.net/goamz/aws"
	"launchpad.net/goamz/s3"
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
	err := r.ParseMultipartForm(0)
	if err != nil {
		internalError(w, err)
	}

	channel := r.FormValue("channel")
	signature := r.FormValue("signature")
	version := r.FormValue("version")
	title := r.FormValue("title")
	notes := r.FormValue("notes")
	if channel != "alpha" && channel != "beta" && channel != "stable" {
		http.Error(w, "Invalid release channel", http.StatusBadRequest)
		return
	}
	if !versionPattern.MatchString(version) {
		http.Error(w, "Invalid version number", http.StatusBadRequest)
		return
	}
	if title == "" {
		http.Error(w, "Missing title", http.StatusBadRequest)
		return
	}
	if signature != "" && !signaturePattern.MatchString(signature) {
		http.Error(w, "Invalid DSA signature", http.StatusBadRequest)
	}
	f, fh, err := r.FormFile("file")
	if err == http.ErrMissingFile {
		http.Error(w, "Missing file", http.StatusBadRequest)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}

	fstat, err := f.(*os.File).Stat()
	if err != nil {
		internalError(w, err)
	}
	length := fstat.Size()
	fileURL, err := uploadFile(f, fh, version, length)
	f.Close()
	if err != nil {
		internalError(w, err)
		return
	}

	var notesURL string
	if notes != "" {
		notesURL, err = uploadReleaseNotes(notes, version)
		if err != nil {
			internalError(w, err)
			return
			// TODO: cleanup uploaded file
		}
	}

	item := &appcast.Item{
		PubDate: time.Now().Format(time.RFC3339),
		Title:   title,
		Enclosure: &appcast.Enclosure{
			URL:       fileURL,
			Length:    strconv.FormatInt(length, 10),
			Type:      "application/octet-stream",
			Version:   version,
			Signature: signature,
		},
	}

	if notesURL != "" {
		item.ReleaseNotesLink = notesURL
	}
	if signature != "" {
		item.Enclosure.Signature = signature
	}

	switch channel {
	case "stable":
		err = updateAppcast(item, "stable")
		if err != nil {
			internalError(w, err)
			return
			// TODO: cleanup uploaded file
		}
		fallthrough
	case "beta":
		err = updateAppcast(item, "beta")
		if err != nil {
			internalError(w, err)
			return
			// TODO: cleanup uploaded file
		}
		fallthrough
	case "alpha":
		err = updateAppcast(item, "alpha")
		if err != nil {
			internalError(w, err)
			return
			// TODO: cleanup uploaded file
		}
	}

	fmt.Fprintf(w, "BOOM!")
}

func uploadFile(f multipart.File, fh *multipart.FileHeader, version string, length int64) (url string, err error) {
	ext := filepath.Ext(fh.Filename)
	filename := appName + "-" + version + ext

	// Check if the file already exists
	// TODO: this should be a HEAD request
	rc, err := s3Bucket.GetReader(filename)
	if rc != nil {
		rc.Close()
	}
	if err != nil {
		if s3err, ok := err.(*s3.Error); ok {
			if s3err.StatusCode != 404 {
				return
			}
		} else {
			return
		}
	} else {
		return "", errors.New("App version already exists")
	}

	err = s3Bucket.PutReader(filename, f, length, "application/octet-stream", s3.PublicRead)
	return s3Bucket.URL(filename), err
}

func uploadReleaseNotes(markdown, version string) (url string, err error) {
	filename := appName + "-" + version + ".html"
	html := blackfriday.MarkdownCommon([]byte(markdown))
	err = s3Bucket.Put(filename, html, "text/html; charset=utf-8", s3.PublicRead)
	return s3Bucket.URL(filename), err
}

func updateAppcast(item *appcast.Item, channel string) error {
	filename := appName + "-" + channel + ".xml"
	current, err := s3Bucket.GetReader(filename)
	if err != nil {
		if s3err, ok := err.(*s3.Error); ok {
			if s3err.StatusCode != 404 {
				return err
			}
		} else {
			return err
		}
	}
	if current != nil {
		defer current.Close()
	}

	feed := &appcast.RSS{
		Version: "2.0",
		Channel: &appcast.Channel{
			Title:       appName,
			Description: fmt.Sprintf("Updates for %s (%s)", appName, channel),
			Link:        s3Bucket.URL(filename),
		},
	}
	if current != nil {
		err = xml.NewDecoder(current).Decode(feed)
		if err != nil {
			return err
		}
	}

	feed.Channel.Items = append([]*appcast.Item{item}, feed.Channel.Items...)
	if len(feed.Channel.Items) > 10 {
		feed.Channel.Items = feed.Channel.Items[:10]
	}

	newFeed, err := xml.Marshal(feed)
	if err != nil {
		return err
	}

	return s3Bucket.Put(filename, newFeed, "text/xml; charset=utf-8", s3.PublicRead)
}

func internalError(w http.ResponseWriter, err error) {
	log.Printf("%T: %s", err, err)
	http.Error(w, err.Error(), http.StatusInternalServerError)
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

var (
	appName  = os.Getenv("APP_NAME")
	s3Bucket = s3.New(aws.Auth{os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY")}, aws.USEast).Bucket(os.Getenv("S3_BUCKET"))
)

func init() {
	for _, env := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "APP_NAME", "S3_BUCKET"} {
		if os.Getenv(env) == "" {
			log.Fatalf("Missing %s environment variable", env)
		}
	}
}
