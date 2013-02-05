package appcast

import (
	"github.com/titanous/go.xml"
)

type RSS struct {
	XMLName xml.Name `xml:"rss"`
	Version string   `xml:"version,attr"`
	Channel *Channel `xml:"channel"`
}

type Channel struct {
	XMLName     xml.Name `xml:"channel"`
	Title       string   `xml:"title"`
	Link        string   `xml:"link"`        // required
	Description string   `xml:"description"` // required
	Items       []*Item  `xml:"item"`
}

type Item struct {
	XMLName   xml.Name   `xml:"item"`
	Title     string     `xml:"title"`             // required
	PubDate   string     `xml:"pubDate,omitempty"` // created or updated
	Enclosure *Enclosure `xml:"enclosure"`

	ReleaseNotesLink string `xml:"sparkle=http://www.andymatuschak.org/xml-namespaces/sparkle releaseNotesLink,omitempty"`
}

type Enclosure struct {
	XMLName   xml.Name `xml:"enclosure"`
	URL       string   `xml:"url,attr"`
	Length    string   `xml:"length,attr"`
	Type      string   `xml:"type,attr"`
	Version   string   `xml:"sparkle=http://www.andymatuschak.org/xml-namespaces/sparkle version,attr"`
	Signature string   `xml:"sparkle=http://www.andymatuschak.org/xml-namespaces/sparkle dsaSignature,attr,omitempty"`
}
