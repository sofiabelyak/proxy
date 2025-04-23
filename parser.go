package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func parseCookies(cookieHeader string) map[string]string {
	cookies := make(map[string]string)
	if cookieHeader == "" {
		return cookies
	}

	for _, cookie := range strings.Split(cookieHeader, ";") {
		parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
		if len(parts) == 2 {
			cookies[parts[0]] = parts[1]
		}
	}

	return cookies
}

func parseFormData(body []byte) map[string]string {
	params := make(map[string]string)
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return params
	}

	for key, value := range values {
		if len(value) > 0 {
			params[key] = value[0]
		}
	}

	return params
}

func parseURL(rawURL string) (string, map[string]string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, make(map[string]string)
	}

	params := make(map[string]string)
	for key, values := range u.Query() {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}

	return u.Path, params
}

func decompressBody(body []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, err
		}
		defer reader.Close()
		return io.ReadAll(reader)
	default:
		return body, nil
	}
}

func ParseRequest(r *http.Request, body []byte) (*ParsedRequest, error) {
	path, getParams := parseURL(r.URL.String())

	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	cookies := parseCookies(r.Header.Get("Cookie"))

	var postParams map[string]string
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		postParams = parseFormData(body)
	}

	body, err := decompressBody(body, r.Header.Get("Content-Encoding"))
	if err != nil {
		return nil, err
	}

	return &ParsedRequest{
		Method:     r.Method,
		Path:       path,
		GetParams:  getParams,
		Headers:    headers,
		Cookies:    cookies,
		PostParams: postParams,
		Body:       string(body),
	}, nil
}

func ParseResponse(resp *http.Response, body []byte) (*ParsedResponse, error) {
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	body, err := decompressBody(body, resp.Header.Get("Content-Encoding"))
	if err != nil {
		return nil, err
	}

	return &ParsedResponse{
		Code:    resp.StatusCode,
		Message: resp.Status,
		Headers: headers,
		Body:    string(body),
	}, nil
}
