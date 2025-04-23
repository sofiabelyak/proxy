package main

import (
	"encoding/json"
	"time"
)

type ParsedRequest struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	GetParams  map[string]string `json:"get_params"`
	Headers    map[string]string `json:"headers"`
	Cookies    map[string]string `json:"cookies"`
	PostParams map[string]string `json:"post_params"`
	Body       string            `json:"body"`
}

type ParsedResponse struct {
	Code    int               `json:"code"`
	Message string            `json:"message"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type RequestRecord struct {
	ID          int
	Request     ParsedRequest
	Response    ParsedResponse
	Timestamp   time.Time
	IsHTTPS     bool
	RawRequest  []byte
	RawResponse []byte
}

func (r *RequestRecord) ToJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"id":           r.ID,
		"request":      r.Request,
		"response":     r.Response,
		"timestamp":    r.Timestamp.Format(time.RFC3339),
		"is_https":     r.IsHTTPS,
		"raw_request":  r.RawRequest,
		"raw_response": r.RawResponse,
	})
}
