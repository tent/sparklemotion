package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"bitbucket.org/gosimple/oauth2"
	"github.com/gorilla/sessions"
	"github.com/russross/blackfriday"
	"github.com/titanous/go.xml"
	"github.com/titanous/goamz/aws"
	"github.com/titanous/goamz/s3"
	"github.com/titanous/sparklemotion/appcast"
)

type indexInfo struct {
	RequireSignature bool

	Version    string
	FileURL    string
	FileLength string
	Signature  string
}

var indexTemplate = template.Must(template.ParseFiles("templates/_layout.html", "templates/index.html"))

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	err := indexTemplate.Execute(w, &indexInfo{
		RequireSignature: requireSig,

		Version:    r.FormValue("version"),
		FileURL:    r.FormValue("url"),
		FileLength: r.FormValue("length"),
		Signature:  r.FormValue("signature"),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

var (
	versionPattern   = regexp.MustCompile(`[0-9]\.[0-9]\w*`)
	signaturePattern = regexp.MustCompile(`[A-Za-z0-9/+]+=*`)
)

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if subtle.ConstantTimeCompare(apiKey, []byte(query.Get("key"))) != 1 {
		http.Error(w, "Incorrect or missing key", http.StatusUnauthorized)
		return
	}
	length, _ := strconv.ParseInt(query.Get("length"), 10, 64)
	if length == 0 {
		http.Error(w, "Missing or invalid length param", http.StatusBadRequest)
		return
	}

	multi, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Invalid multipart body", http.StatusBadRequest)
		return
	}

	var version, url string
	for {
		part, err := multi.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Invalid multipart body", http.StatusBadRequest)
			return
		}

		name := part.FormName()
		if name == "" {
			continue
		}
		filename := part.FileName()
		if filename != "" && version == "" {
			http.Error(w, "Version must be before file in multipart body", http.StatusBadRequest)
			return
		}

		if name == "version" {
			b := &bytes.Buffer{}
			_, err := b.ReadFrom(part)
			if err != nil {
				http.Error(w, "Error reading version part", http.StatusInternalServerError)
				return
			}

			version = b.String()
			if !versionPattern.MatchString(version) {
				http.Error(w, "Invalid version number", http.StatusBadRequest)
				return
			}
		}

		if filename != "" {
			url, err = uploadFile(part, filename, version, length)
			if err != nil {
				internalError(w, err)
				return
			}
			break
		}
	}
	w.Write([]byte(url))
}

func pushHandler(w http.ResponseWriter, r *http.Request) {
	// Force all file parts to be written to disk so that we can get the size from the filesystem
	err := r.ParseMultipartForm(0)
	if err != nil {
		internalError(w, err)
	}

	channel := r.FormValue("channel")
	signature := r.FormValue("signature")
	version := r.FormValue("version")
	title := r.FormValue("title")
	notes := r.FormValue("notes")
	fileURL := r.FormValue("url")
	fileLength := r.FormValue("length")
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
	if requireSig && signature == "" {
		http.Error(w, "Missing signature", http.StatusBadRequest)
		return
	}
	if signature != "" && !signaturePattern.MatchString(signature) {
		http.Error(w, "Invalid DSA signature", http.StatusBadRequest)
		return
	}
	length, _ := strconv.ParseInt(fileLength, 10, 64)
	if fileURL != "" && length == 0 {
		http.Error(w, "Invalid file length", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	// Push 2KB down the wire so that Chrome starts partial rendering of our streaming response
	fmt.Fprint(w, strings.Repeat(" ", 2048))

	if fileURL == "" {
		f, fh, err := r.FormFile("file")
		if err == http.ErrMissingFile {
			http.Error(w, "Missing file", http.StatusBadRequest)
			return
		}
		if err != nil {
			internalError(w, err)
			return
		}

		writeStatus(w, "Uploading binary to S3...")

		fstat, err := f.(*os.File).Stat()
		if err != nil {
			internalError(w, err)
		}
		length = fstat.Size()
		fileURL, err = uploadFile(f, fh.Filename, version, length)
		f.Close()
		if err != nil {
			internalError(w, err)
			return
		}
	}

	var notesURL string
	if notes != "" {
		writeStatus(w, "Uploading release notes...")
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
		writeStatus(w, "Updating stable appcast...")
		err = updateAppcast(item, "stable")
		if err != nil {
			internalError(w, err)
			return
			// TODO: cleanup uploaded file
		}
		writeStatus(w, "Updating latest redirect...")
		err = updateLatestRedirect("stable", fileURL)
		if err != nil {
			internalError(w, err)
			return
		}
		fallthrough
	case "beta":
		writeStatus(w, "Updating beta appcast...")
		err = updateAppcast(item, "beta")
		if err != nil {
			internalError(w, err)
			return
			// TODO: cleanup uploaded file
		}
		writeStatus(w, "Updating latest redirect...")
		err = updateLatestRedirect("beta", fileURL)
		if err != nil {
			internalError(w, err)
			return
		}
		fallthrough
	case "alpha":
		writeStatus(w, "Updating alpha appcast...")
		err = updateAppcast(item, "alpha")
		if err != nil {
			internalError(w, err)
			return
			// TODO: cleanup uploaded file
		}
		writeStatus(w, "Updating latest redirect...")
		err = updateLatestRedirect("alpha", fileURL)
		if err != nil {
			internalError(w, err)
			return
		}
	}

	writeStatus(w, "BOOM!")
}

func uploadFile(f io.Reader, name string, version string, length int64) (url string, err error) {
	ext := filepath.Ext(name)
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

	feed := &appcast.RSS{
		Version: "2.0",
		Channel: &appcast.Channel{
			Title:       appName,
			Description: fmt.Sprintf("Updates for %s (%s)", appName, channel),
			Link:        s3Bucket.URL(filename),
		},
	}
	if current != nil {
		defer current.Close()
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

func updateLatestRedirect(channel, url string) error {
	headers := map[string][]string{
		"Content-Length":                  {"0"},
		"Content-Type":                    {"text/html"},
		"x-amz-acl":                       {string(s3.PublicRead)},
		"x-amz-website-redirect-location": {url},
	}
	return s3Bucket.PutWithHeaders(appName+"-"+channel, strings.NewReader(""), headers)
}

func writeStatus(w http.ResponseWriter, msg string) {
	fmt.Fprintf(w, "<p>%s</p>", msg)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func internalError(w http.ResponseWriter, err error) {
	log.Printf("%T: %s", err, err)
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

var cookieStore = sessions.NewCookieStore([]byte(os.Getenv("COOKIE_SECRET")))

func protect(action http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if baseURL.Scheme == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			if r.Header.Get("X-Forwarded-Proto") != "https" {
				http.Redirect(w, r, baseURL.ResolveReference(r.URL).String(), http.StatusMovedPermanently)
				return
			}
		}

		sess := getSession(r)
		var authorized bool
		if sess.Values["user"] != nil {
			for _, u := range authUsers {
				if sess.Values["user"].(string) == u {
					authorized = true
					break
				}
			}
		} else {
			http.Redirect(w, r, "/auth", http.StatusFound)
			return
		}

		if authorized {
			action(w, r)
		} else {
			http.Error(w, "You're not allowed here!", http.StatusForbidden)
		}
	}
}

func randString(bytes int) string {
	b := make([]byte, bytes)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getSession(r *http.Request) *sessions.Session {
	s, _ := cookieStore.Get(r, "sparklemotion")
	return s
}

func authSetupHandler(w http.ResponseWriter, r *http.Request) {
	state := randString(8)
	sess := getSession(r)
	sess.Values["state"] = state
	sess.Values["return"] = r.URL.String()
	sess.Save(r, w)
	http.Redirect(w, r, githubAuth.GetAuthorizeURL(state), http.StatusFound)
}

type githubUser struct {
	Login string `json:"login"`
}

func authFinalizeHandler(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r)
	if sess.Values["state"] == nil || r.FormValue("state") != sess.Values["state"].(string) {
		http.Error(w, "Invalid session state", http.StatusBadRequest)
	}
	delete(sess.Values, "state")

	token, err := githubAuth.GetAccessToken(r.FormValue("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	github := oauth2.Request("https://api.github.com/", token.AccessToken)
	github.AccessTokenInHeader = true
	github.AccessTokenInHeaderScheme = "token"
	userInfo, err := github.Get("user")
	if err != nil {
		internalError(w, err)
		return
	}
	defer userInfo.Body.Close()
	user := &githubUser{}
	err = json.NewDecoder(userInfo.Body).Decode(user)
	if err != nil {
		internalError(w, err)
		return
	}

	url := sess.Values["return"]
	if url == nil {
		url = "/"
	}
	delete(sess.Values, "return")
	sess.Values["user"] = user.Login
	sess.Save(r, w)
	http.Redirect(w, r, url.(string), http.StatusFound)
}

func main() {
	http.HandleFunc("/", protect(indexHandler))
	http.HandleFunc("/push", protect(pushHandler))
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/auth", authSetupHandler)
	http.HandleFunc("/auth/return", authFinalizeHandler)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

var (
	appName    = os.Getenv("APP_NAME")
	s3Bucket   = s3.New(aws.Auth{os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY")}, aws.USEast).Bucket(os.Getenv("S3_BUCKET"))
	authUsers  = strings.Split(os.Getenv("AUTHORIZED_USERS"), ",")
	apiKey     = []byte(os.Getenv("API_KEY"))
	requireSig = os.Getenv("REQUIRE_SIGNATURE") != ""
	githubAuth *oauth2.OAuth2Service
	baseURL    *url.URL
)

func init() {
	e := []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "APP_NAME", "S3_BUCKET", "COOKIE_SECRET", "AUTHORIZED_USERS", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "BASE_URL", "API_KEY"}
	for _, env := range e {
		if os.Getenv(env) == "" {
			log.Fatalf("Missing %s environment variable", env)
		}
	}

	var err error
	baseURL, err = url.Parse(os.Getenv("BASE_URL"))
	if err != nil {
		log.Fatal("Invalid BASE_URL:", err)
	}

	githubAuth = oauth2.Service(os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET"), "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token")
	ret, _ := url.Parse("/auth/return")
	githubAuth.RedirectURL = baseURL.ResolveReference(ret).String()
}
