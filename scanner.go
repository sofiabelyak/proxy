package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var paramDictionary = []string{
	"id", "page", "view", "file", "path", "dir", "search", "query", "q", "s",
	"keyword", "lang", "category", "type", "sort", "order", "filter", "from",
	"to", "date", "time", "year", "month", "day", "hour", "minute", "second",
	"user", "username", "name", "email", "mail", "password", "pass", "pwd",
	"token", "key", "secret", "auth", "session", "cookie", "state", "code",
	"redirect", "return", "callback", "url", "uri", "link", "next", "prev",
	"debug", "test", "admin", "root", "system", "config", "setting", "option",
	"mode", "action", "do", "cmd", "exec", "run", "load", "save", "delete",
	"remove", "add", "create", "update", "edit", "modify", "change", "set",
	"get", "post", "put", "patch", "delete", "head", "options", "trace",
	"connect", "proxy", "forward", "back", "refresh", "reload", "restart",
	"stop", "start", "pause", "resume", "continue", "cancel", "abort", "exit",
	"quit", "close", "open", "show", "hide", "display", "print", "export",
	"import", "upload", "download", "sync", "backup", "restore", "reset",
	"clear", "flush", "purge", "clean", "optimize", "repair", "check", "verify",
	"validate", "test", "scan", "monitor", "log", "trace", "debug", "profile",
	"benchmark", "measure", "count", "sum", "avg", "min", "max", "first",
	"last", "prev", "next", "random", "sample", "limit", "offset", "page",
	"size", "count", "total", "all", "any", "none", "some", "many", "few",
	"more", "less", "equal", "not", "and", "or", "xor", "nor", "nand", "xnor",
	"true", "false", "null", "undefined", "empty", "full", "partial", "complete",
	"success", "failure", "error", "warning", "info", "debug", "trace", "fatal",
	"critical", "major", "minor", "trivial", "blocker", "enhancement", "feature",
	"bug", "issue", "task", "todo", "fixme", "xxx", "hack", "kludge", "workaround",
	"solution", "answer", "result", "output", "input", "source", "target",
	"destination", "origin", "referer", "user-agent", "accept", "content-type",
	"content-length", "content-encoding", "content-language", "content-location",
	"content-md5", "content-range", "content-disposition", "content-security-policy",
	"x-frame-options", "x-xss-protection", "x-content-type-options", "x-powered-by",
	"server", "date", "expires", "last-modified", "etag", "cache-control",
	"pragma", "connection", "keep-alive", "upgrade", "via", "warning", "vary",
	"age", "allow", "location", "retry-after", "server-timing", "strict-transport-security",
	"transfer-encoding", "www-authenticate", "x-forwarded-for", "x-forwarded-host",
	"x-forwarded-proto", "x-real-ip", "x-request-id", "x-requested-with",
	"x-ua-compatible", "x-webkit-csp", "x-content-duration", "x-content-security-policy",
	"x-content-type-options", "x-download-options", "x-frame-options", "x-permitted-cross-domain-policies",
	"x-powered-by", "x-robots-tag", "x-ua-compatible", "x-webkit-csp", "x-xss-protection",
}

func generateRandomValue() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func scanForHiddenParams(record *RequestRecord) ([]string, error) {
	path := record.Request.Path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		path = "http://" + path
	}

	baseURL, err := url.Parse(path)
	if err != nil {
		return []string{}, fmt.Errorf("failed to parse URL: %v", err)
	}

	log.Printf("Scanning URL: %s", baseURL.String())

	foundParams := make([]string, 0)
	results := make(chan string)
	var wg sync.WaitGroup

	for _, param := range paramDictionary {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			testURL := *baseURL
			query := testURL.Query()

			originalParams := make(url.Values)
			for k, v := range query {
				originalParams[k] = v
			}

			randomValue := generateRandomValue()
			query.Set(p, randomValue)
			testURL.RawQuery = query.Encode()

			log.Printf("Testing parameter %s=%s on URL %s", p, randomValue, testURL.String())

			req, err := http.NewRequest(record.Request.Method, testURL.String(), bytes.NewReader([]byte(record.Request.Body)))
			if err != nil {
				log.Printf("Error creating request for param %s: %v", p, err)
				return
			}

			for key, value := range record.Request.Headers {
				req.Header.Set(key, value)
			}

			client := &http.Client{
				Timeout: 10 * time.Second,
			}
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("Error sending request for param %s: %v", p, err)
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Error reading response for param %s: %v", p, err)
				return
			}

			log.Printf("Response for %s: %s", p, string(body))

			if bytes.Contains(body, []byte(randomValue)) {
				log.Printf("Found parameter %s with value %s", p, randomValue)
				results <- p
			}
		}(param)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for param := range results {
		foundParams = append(foundParams, param)
	}

	log.Printf("Scan completed. Found parameters: %v", foundParams)
	return foundParams, nil
}
