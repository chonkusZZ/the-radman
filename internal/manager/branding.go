package manager

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

const maxLogoBytes = 256 << 10

// Branding is the optional custom logo shown in the UI.
type Branding struct {
	SVG       string `json:"svg"`
	SourceURL string `json:"source_url"`
	Version   int64  `json:"version"`
}

func (a *App) Branding(ctx context.Context) Branding {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.brand == nil {
		var b Branding
		a.St.GetJSON(ctx, "branding", &b)
		a.brand = &b
	}
	return *a.brand
}

func (a *App) SaveBranding(ctx context.Context, b Branding) error {
	b.Version = time.Now().Unix()
	if err := a.St.SetJSON(ctx, "branding", b); err != nil {
		return err
	}
	a.mu.Lock()
	a.brand = &b
	a.mu.Unlock()
	return nil
}

// validateSVG accepts only static, script-free SVG documents.
// The logo is served from our own origin, so anything active is rejected rather than "cleaned".
func validateSVG(b []byte) error {
	if len(b) == 0 {
		return errors.New("the file is empty")
	}
	if len(b) > maxLogoBytes {
		return fmt.Errorf("logo is larger than %d KB", maxLogoBytes>>10)
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true
	banned := map[string]bool{"script": true, "foreignobject": true, "iframe": true, "object": true, "embed": true,
		"audio": true, "video": true, "animate": true, "set": true, "animatetransform": true, "animatemotion": true}
	sawRoot := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("not valid XML: %v", err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			if strings.Contains(strings.ToUpper(string(t)), "ENTITY") {
				return errors.New("entity declarations are not allowed")
			}
		case xml.StartElement:
			name := strings.ToLower(t.Name.Local)
			if !sawRoot {
				if name != "svg" {
					return errors.New("the file is not an SVG image (root element is <" + t.Name.Local + ">)")
				}
				sawRoot = true
			}
			if banned[name] {
				return fmt.Errorf("<%s> elements are not allowed in a logo", t.Name.Local)
			}
			for _, at := range t.Attr {
				an, av := strings.ToLower(at.Name.Local), strings.ToLower(strings.TrimSpace(at.Value))
				if strings.HasPrefix(an, "on") {
					return fmt.Errorf("event handler attribute %q is not allowed", at.Name.Local)
				}
				if strings.Contains(av, "javascript:") {
					return errors.New("javascript: URLs are not allowed")
				}
				if an == "href" && !(strings.HasPrefix(av, "#") || strings.HasPrefix(av, "data:image/")) {
					return errors.New("external references are not allowed (embed the image or use #id references)")
				}
			}
		}
	}
	if !sawRoot {
		return errors.New("no <svg> element found")
	}
	return nil
}

// fetchSVG downloads a logo from a URL once; it is then stored and served locally.
func fetchSVG(raw string) ([]byte, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("enter a full http(s):// URL")
	}
	d := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, _ := net.SplitHostPort(address)
		if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return errors.New("refusing to fetch from a loopback/link-local address")
		}
		return nil
	}}
	c := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DialContext: d.DialContext}}
	resp, err := c.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server answered HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxLogoBytes+1))
	if err != nil {
		return nil, err
	}
	return b, validateSVG(b)
}

func (s *server) logo(w http.ResponseWriter, r *http.Request) {
	b := s.a.Branding(r.Context())
	if b.SVG == "" {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "image/svg+xml")
	// If someone opens the file directly, the sandbox directive stops any script from running on our origin.
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox")
	h.Set("Cache-Control", "public, max-age=3600")
	w.Write([]byte(b.SVG))
}

func (s *server) settingsBranding(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	back := func(kind, msg string) { s.back(w, r, "/settings?tab=branding", kind, msg) }
	switch r.PostFormValue("action") {
	case "remove":
		if err := s.a.SaveBranding(ctx, Branding{}); err != nil {
			s.fail(w, r, u, err)
			return
		}
		s.a.Audit(ctx, u.Email, "branding.logo_removed", "")
		back("ok", "Logo removed.")
	case "upload":
		f, _, err := r.FormFile("file")
		if err != nil {
			back("err", "Choose an SVG file to upload.")
			return
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, maxLogoBytes+1))
		if err == nil {
			err = validateSVG(b)
		}
		if err != nil {
			back("err", "That file can't be used as a logo: "+err.Error())
			return
		}
		s.a.SaveBranding(ctx, Branding{SVG: string(b)})
		s.a.Audit(ctx, u.Email, "branding.logo_uploaded", "")
		back("ok", "Logo updated.")
	case "url":
		src := strings.TrimSpace(r.PostFormValue("url"))
		b, err := fetchSVG(src)
		if err != nil {
			back("err", "Could not use that URL: "+err.Error())
			return
		}
		s.a.SaveBranding(ctx, Branding{SVG: string(b), SourceURL: src})
		s.a.Audit(ctx, u.Email, "branding.logo_url", src)
		back("ok", "Logo downloaded and saved. It is stored in the manager and served from there, so the original site is not contacted on page views.")
	default:
		http.NotFound(w, r)
	}
}
