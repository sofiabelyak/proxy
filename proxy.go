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

type Storage struct {
	mu sync.RWMutex
	db *DB
}

func NewStorage() (*Storage, error) {
	db, err := NewDB()
	if err != nil {
		return nil, err
	}

	if err = db.Init(); err != nil {
		return nil, err
	}

	return &Storage{db: db}, nil
}

func (s *Storage) Add(r *http.Request, reqBody []byte, resp *http.Response, respBody []byte, isHTTPS bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	parsedRequest, err := ParseRequest(r, reqBody)
	if err != nil {
		return 0, err
	}

	parsedResponse, err := ParseResponse(resp, respBody)
	if err != nil {
		return 0, err
	}

	record := &RequestRecord{
		Request:     *parsedRequest,
		Response:    *parsedResponse,
		Timestamp:   time.Now(),
		IsHTTPS:     isHTTPS,
		RawRequest:  reqBody,
		RawResponse: respBody,
	}

	if err = s.db.SaveRequest(record); err != nil {
		return 0, err
	}

	return record.ID, nil
}

func (s *Storage) GetAll() ([]*RequestRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db.GetAllRequests()
}

func (s *Storage) GetByID(id int) (*RequestRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db.GetRequest(id)
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

		targetURL := "http://" + targetHost
		if r.TLS != nil {
			targetURL = "https://" + targetHost
		}
		targetPath := r.URL.Path
		if r.URL.RawQuery != "" {
			targetPath += "?" + r.URL.RawQuery
		}
		targetURL += targetPath

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading body", http.StatusInternalServerError)
			return
		}
		r.Body.Close()

		req, err := http.NewRequest(
			r.Method,
			targetURL,
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

		storage.Add(r, bodyBytes, resp, respBodyBytes, r.TLS != nil)

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
		records, err := storage.GetAll()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		summaries := make([]map[string]interface{}, len(records))
		for i, record := range records {
			summaries[i] = map[string]interface{}{
				"id":          record.ID,
				"method":      record.Request.Method,
				"url":         record.Request.Path,
				"status_code": record.Response.Code,
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
		record, err := storage.GetByID(id)
		if err != nil {
			http.Error(w, "Request not found", http.StatusNotFound)
			return
		}
		detail := map[string]interface{}{
			"id":                   record.ID,
			"method":               record.Request.Method,
			"url":                  record.Request.Path,
			"request_headers":      record.Request.Headers,
			"request_body":         base64.StdEncoding.EncodeToString([]byte(record.Request.Body)),
			"response_status":      record.Response.Message,
			"response_status_code": record.Response.Code,
			"response_headers":     record.Response.Headers,
			"response_body":        base64.StdEncoding.EncodeToString([]byte(record.Response.Body)),
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

		record, err := storage.GetByID(id)
		if err != nil {
			http.Error(w, "Request not found", http.StatusNotFound)
			return
		}

		var resp *http.Response

		if record.IsHTTPS {
			conf := &tls.Config{
				InsecureSkipVerify: true,
			}

			targetURL, err := url.Parse(record.Request.Path)
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
				record.Request.Method,
				record.Request.Path,
				bytes.NewReader([]byte(record.Request.Body)),
			)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			for key, value := range record.Request.Headers {
				req.Header.Set(key, value)
			}
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
				record.Request.Method,
				record.Request.Path,
				bytes.NewReader([]byte(record.Request.Body)),
			)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			for key, value := range record.Request.Headers {
				req.Header.Set(key, value)
			}
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

		record, err := storage.GetByID(id)
		if err != nil {
			http.Error(w, "Request not found", http.StatusNotFound)
			return
		}

		hiddenParams, err := scanForHiddenParams(record)
		if err != nil {
			http.Error(w, "Error scanning for parameters", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "scan completed",
			"headers":       record.Request.Headers,
			"hidden_params": hiddenParams,
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

	storage, err := NewStorage()
	if err != nil {
		log.Fatal(err)
	}

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
