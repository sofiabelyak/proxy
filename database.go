package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

type DB struct {
	*sql.DB
}

func NewDB() (*DB, error) {
	host := os.Getenv("POSTGRES_HOST")
	if host == "" {
		host = "localhost"
	}

	port := os.Getenv("POSTGRES_PORT")
	if port == "" {
		port = "5432"
	}

	user := os.Getenv("POSTGRES_USER")
	if user == "" {
		user = "postgres"
	}

	password := os.Getenv("POSTGRES_PASSWORD")
	if password == "" {
		password = "postgres"
	}

	dbname := os.Getenv("POSTGRES_DB")
	if dbname == "" {
		dbname = "proxy_db"
	}

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 10; i++ {
		if err = db.Ping(); err == nil {
			break
		}
		log.Printf("Waiting for database to be ready... (attempt %d/10)", i+1)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return nil, err
	}

	return &DB{db}, nil
}

func (db *DB) Init() error {
	query := `
	CREATE TABLE IF NOT EXISTS requests (
		id SERIAL PRIMARY KEY,
		request JSONB NOT NULL,
		response JSONB NOT NULL,
		timestamp TIMESTAMP NOT NULL,
		is_https BOOLEAN NOT NULL,
		raw_request BYTEA,
		raw_response BYTEA
	)`

	_, err := db.Exec(query)
	return err
}

func (db *DB) SaveRequest(record *RequestRecord) error {
	requestJSON, err := json.Marshal(record.Request)
	if err != nil {
		return err
	}

	responseJSON, err := json.Marshal(record.Response)
	if err != nil {
		return err
	}

	query := `
	INSERT INTO requests (request, response, timestamp, is_https, raw_request, raw_response)
	VALUES ($1, $2, $3, $4, $5, $6)
	RETURNING id`

	err = db.QueryRow(
		query,
		requestJSON,
		responseJSON,
		record.Timestamp,
		record.IsHTTPS,
		record.RawRequest,
		record.RawResponse,
	).Scan(&record.ID)

	return err
}

func (db *DB) GetRequest(id int) (*RequestRecord, error) {
	var record RequestRecord
	var requestJSON, responseJSON []byte

	query := `
	SELECT id, request, response, timestamp, is_https, raw_request, raw_response
	FROM requests WHERE id = $1`

	err := db.QueryRow(query, id).Scan(
		&record.ID,
		&requestJSON,
		&responseJSON,
		&record.Timestamp,
		&record.IsHTTPS,
		&record.RawRequest,
		&record.RawResponse,
	)

	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(requestJSON, &record.Request); err != nil {
		return nil, err
	}

	if err = json.Unmarshal(responseJSON, &record.Response); err != nil {
		return nil, err
	}

	return &record, nil
}

func (db *DB) GetAllRequests() ([]*RequestRecord, error) {
	query := `
	SELECT id, request, response, timestamp, is_https, raw_request, raw_response
	FROM requests ORDER BY timestamp DESC`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*RequestRecord
	for rows.Next() {
		var record RequestRecord
		var requestJSON, responseJSON []byte

		err := rows.Scan(
			&record.ID,
			&requestJSON,
			&responseJSON,
			&record.Timestamp,
			&record.IsHTTPS,
			&record.RawRequest,
			&record.RawResponse,
		)
		if err != nil {
			return nil, err
		}

		if err = json.Unmarshal(requestJSON, &record.Request); err != nil {
			return nil, err
		}

		if err = json.Unmarshal(responseJSON, &record.Response); err != nil {
			return nil, err
		}

		records = append(records, &record)
	}

	return records, nil
}
