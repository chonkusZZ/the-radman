// Package store wraps the PostgreSQL connection pool.
package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

// Store holds the primary pool and an optional read-only pool (a streaming replica) for heavy read queries
// such as logs and dashboards. RO equals DB when no replica is configured.
type Store struct {
	DB *pgxpool.Pool
	RO *pgxpool.Pool
}

var ErrNotFound = pgx.ErrNoRows

func Open(ctx context.Context, url string) (*Store, error) {
	var pool *pgxpool.Pool
	var err error
	for i := 0; i < 30; i++ { // wait for the DB when starting alongside it (compose)
		pool, err = pgxpool.New(ctx, url)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				break
			}
			pool.Close()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, err
	}
	return &Store{DB: pool, RO: pool}, nil
}

func (s *Store) GetJSON(ctx context.Context, key string, v any) error {
	var raw []byte
	err := s.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // leave v at its defaults
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (s *Store) SetJSON(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, key, b)
	return err
}

func (s *Store) GetSecret(ctx context.Context, key string) (string, error) {
	var v string
	err := s.DB.QueryRow(ctx, `SELECT value FROM secrets WHERE key=$1`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *Store) SetSecret(ctx context.Context, key, val string) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO secrets(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, key, val)
	return err
}

func (s *Store) DelSecret(ctx context.Context, key string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM secrets WHERE key=$1`, key)
	return err
}

// AttachReplica routes read-heavy queries to a replica. A failing replica silently falls back to the primary is NOT done
// on purpose: stale or missing logs are better surfaced than hidden, so connection errors propagate to the caller.
func (s *Store) AttachReplica(ctx context.Context, url string) error {
	p, err := pgxpool.New(ctx, url)
	if err != nil {
		return err
	}
	if err := p.Ping(ctx); err != nil {
		p.Close()
		return err
	}
	s.RO = p
	return nil
}
