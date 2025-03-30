package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

type RequestRecord struct {
	ID                 int
	Method             string
	URL                string
	RequestHeaders     http.Header
	RequestBody        []byte
	ResponseStatus     string
	ResponseStatusCode int
	ResponseHeaders    http.Header
	ResponseBody       []byte
	Timestamp          time.Time
	IsHTTPS            bool
}

type Storage struct {
	mu       sync.RWMutex
	requests []RequestRecord
	nextID   int
}

func (s *Storage) Add(r *http.Request, reqBody []byte, resp *http.Response, respBody []byte, isHTTPS bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanedHeaders := r.Header.Clone()
	cleanedHeaders.Del("Proxy-Connection")
	cleanedHeaders.Del("Proxy-Authorization")

	record := RequestRecord{
		ID:                 s.nextID,
		Method:             r.Method,
		URL:                r.URL.String(),
		RequestHeaders:     cleanedHeaders,
		RequestBody:        reqBody,
		ResponseStatus:     resp.Status,
		ResponseStatusCode: resp.StatusCode,
		ResponseHeaders:    resp.Header.Clone(),
		ResponseBody:       respBody,
		Timestamp:          time.Now(),
		IsHTTPS:            isHTTPS,
	}
	s.requests = append(s.requests, record)
	s.nextID++
	return record.ID
}

func (s *Storage) GetAll() []RequestRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.requests
}

func (s *Storage) GetByID(id int) (*RequestRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.requests {
		if r.ID == id {
			return &r, true
		}
	}
	return nil, false
}

func handleTunneling(w http.ResponseWriter, r *http.Request, storage *Storage) {
	host := r.URL.Host
	if _, port, _ := net.SplitHostPort(host); port == "" {
		host = net.JoinHostPort(host, "443")
	}

	destConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	storage.Add(r, nil, &http.Response{
		Status:     "200 Connection Established",
		StatusCode: 200,
	}, nil, true)

	go transfer(destConn, clientConn)
	transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func proxyHandler(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleTunneling(w, r, storage)
			return
		}

		targetHost := r.Host
		if targetHost == "" {
			http.Error(w, "Missing Host header", http.StatusBadRequest)
			return
		}

		targetPath := r.URL.Path
		if r.URL.RawQuery != "" {
			targetPath += "?" + r.URL.RawQuery
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading body", http.StatusInternalServerError)
			return
		}
		r.Body.Close()

		req, err := http.NewRequest(
			r.Method,
			"http://"+targetHost+targetPath,
			bytes.NewReader(bodyBytes),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		req.Header = r.Header.Clone()
		req.Header.Del("Proxy-Connection")
		req.Header.Del("Proxy-Authorization")

		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		respBodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Error reading response", http.StatusInternalServerError)
			return
		}

		storage.Add(r, bodyBytes, resp, respBodyBytes, false)

		for name, values := range resp.Header {
			w.Header()[name] = values
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(respBodyBytes)
	}
}

func setupAPIRouter(storage *Storage) http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/requests", func(w http.ResponseWriter, r *http.Request) {
		records := storage.GetAll()
		summaries := make([]map[string]interface{}, len(records))
		for i, record := range records {
			summaries[i] = map[string]interface{}{
				"id":          record.ID,
				"method":      record.Method,
				"url":         record.URL,
				"status_code": record.ResponseStatusCode,
				"timestamp":   record.Timestamp.Format(time.RFC3339),
				"is_https":    record.IsHTTPS,
			}
		}
		json.NewEncoder(w).Encode(summaries)
	}).Methods("GET")

	r.HandleFunc("/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid ID", http.StatusBadRequest)
			return
		}
		record, found := storage.GetByID(id)
		if !found {
			http.Error(w, "Request not found", http.StatusNotFound)
			return
		}
		detail := map[string]interface{}{
			"id":                   record.ID,
			"method":               record.Method,
			"url":                  record.URL,
			"request_headers":      record.RequestHeaders,
			"request_body":         base64.StdEncoding.EncodeToString(record.RequestBody),
			"response_status":      record.ResponseStatus,
			"response_status_code": record.ResponseStatusCode,
			"response_headers":     record.ResponseHeaders,
			"response_body":        base64.StdEncoding.EncodeToString(record.ResponseBody),
			"timestamp":            record.Timestamp.Format(time.RFC3339),
			"is_https":             record.IsHTTPS,
		}
		json.NewEncoder(w).Encode(detail)
	}).Methods("GET")

	r.HandleFunc("/repeat/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid ID", http.StatusBadRequest)
			return
		}

		record, found := storage.GetByID(id)
		if !found {
			http.Error(w, "Request not found", http.StatusNotFound)
			return
		}

		var resp *http.Response

		if record.IsHTTPS {
			conf := &tls.Config{
				InsecureSkipVerify: true,
			}

			targetURL, err := url.Parse(record.URL)
			if err != nil {
				http.Error(w, "Invalid URL", http.StatusBadRequest)
				return
			}

			conn, err := tls.Dial("tcp", targetURL.Host, conf)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer conn.Close()

			req, err := http.NewRequest(
				record.Method,
				record.URL,
				bytes.NewReader(record.RequestBody),
			)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			req.Header = record.RequestHeaders.Clone()
			req.Header.Del("Proxy-Connection")
			req.Header.Del("Proxy-Authorization")

			err = req.Write(conn)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}

			resp, err = http.ReadResponse(bufio.NewReader(conn), req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
		} else {
			req, err := http.NewRequest(
				record.Method,
				record.URL,
				bytes.NewReader(record.RequestBody),
			)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			req.Header = record.RequestHeaders.Clone()
			req.Header.Del("Proxy-Connection")
			req.Header.Del("Proxy-Authorization")

			client := &http.Client{
				Timeout: 30 * time.Second,
			}
			resp, err = client.Do(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
		}

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Error reading response", http.StatusInternalServerError)
			return
		}

		for name, values := range resp.Header {
			if name == "Connection" || name == "Keep-Alive" ||
				name == "Proxy-Authenticate" || name == "Proxy-Authorization" ||
				name == "TE" || name == "Trailers" || name == "Transfer-Encoding" ||
				name == "Upgrade" {
				continue
			}
			w.Header()[name] = values
		}

		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
	}).Methods("GET")

	r.HandleFunc("/scan/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid ID", http.StatusBadRequest)
			return
		}

		record, found := storage.GetByID(id)
		if !found {
			http.Error(w, "Request not found", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "headers scanned",
			"headers": record.RequestHeaders,
		})
	}).Methods("GET")

	return r
}

func generateCertificates() {
	if _, err := os.Stat("ca.crt"); os.IsNotExist(err) {
		cmd := exec.Command("openssl", "genrsa", "-out", "ca.key", "2048")
		cmd.Run()
		cmd = exec.Command("openssl", "req", "-new", "-x509", "-days", "3650",
			"-key", "ca.key", "-out", "ca.crt",
			"-subj", "/CN=yngwie proxy CA")
		cmd.Run()

		cmd = exec.Command("openssl", "genrsa", "-out", "cert.key", "2048")
		cmd.Run()

		os.Mkdir("certs", 0755)
	}
}

func main() {
	generateCertificates()

	storage := &Storage{}

	cert, err := tls.LoadX509KeyPair("certs/cert.pem", "certs/cert.key")
	caCert, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	proxy := &http.Server{
		Addr:         ":8080",
		Handler:      proxyHandler(storage),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig:    tlsConfig,
	}

	api := &http.Server{
		Addr:    ":8000",
		Handler: setupAPIRouter(storage),
	}

	go func() {
		log.Println("Proxy server starting on :8080")
		if err := proxy.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	log.Println("API server starting on :8000")
	if err := api.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
