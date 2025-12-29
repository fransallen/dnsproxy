package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// webProxyTarget is the target URL to proxy web requests to.
const webProxyTarget = "https://puredns.pages.dev"

// isWebPath checks if the given path should be handled by the web proxy.
// Reserved paths: /, /_next/*, /images/*, /favicon.ico, /ping
func isWebPath(path string) bool {
	if path == "/" || path == "/favicon.ico" || path == "/ping" {
		return true
	}

	if strings.HasPrefix(path, "/_next/") || strings.HasPrefix(path, "/images/") {
		return true
	}

	return false
}

// serveWeb proxies the request to the puredns.pages.dev website.
func (p *Proxy) serveWeb(w http.ResponseWriter, r *http.Request) {
	// Handle /ping endpoint
	if r.URL.Path == "/ping" {
		w.Header().Set(httphdr.ContentType, "text/plain; charset=utf-8")
		w.Header().Set(httphdr.Server, "puredns")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong"))
		return
	}

	target, err := url.Parse(webProxyTarget)
	if err != nil {
		p.logger.Error("parsing web proxy target", slogutil.KeyError, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Create a reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Customize the director to modify the request
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
	}

	// Custom error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		p.logger.Error("proxying web request", slogutil.KeyError, err, "path", r.URL.Path)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}

	// Modify response headers
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Remove headers from proxied site
		resp.Header.Del("Nel")
		resp.Header.Del("Report-To")

		// Set custom server header
		resp.Header.Set(httphdr.Server, "puredns")
		return nil
	}

	p.logger.Debug("proxying web request", "path", r.URL.Path, "target", webProxyTarget)

	// Serve the proxied request
	proxy.ServeHTTP(w, r)
}

// ServeHTTPRedirect handles HTTP requests and redirects them to HTTPS.
func (p *Proxy) ServeHTTPRedirect(w http.ResponseWriter, r *http.Request) {
	// Build redirect URL: https://puredns.org + request path
	redirectURL := "https://puredns.org" + r.URL.Path
	if r.URL.RawQuery != "" {
		redirectURL += "?" + r.URL.RawQuery
	}

	p.logger.Debug("redirecting http to https", "path", r.URL.Path, "redirect", redirectURL)

	http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
}
