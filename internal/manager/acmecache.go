package manager

import (
	"context"

	"golang.org/x/crypto/acme/autocert"
)

// dbCache stores Let's Encrypt account keys and certificates in PostgreSQL (encrypted with the master key) so that
// several manager instances behind a load balancer share them instead of each requesting its own certificate.
type dbCache struct{ a *App }

func (c *dbCache) Get(ctx context.Context, key string) ([]byte, error) {
	var enc []byte
	if err := c.a.St.DB.QueryRow(ctx, `SELECT data FROM acme_cache WHERE key=$1`, key).Scan(&enc); err != nil {
		return nil, autocert.ErrCacheMiss
	}
	b, err := c.a.Box.Open(string(enc))
	if err != nil {
		return nil, autocert.ErrCacheMiss
	}
	return b, nil
}

func (c *dbCache) Put(ctx context.Context, key string, data []byte) error {
	_, err := c.a.St.DB.Exec(ctx, `INSERT INTO acme_cache(key,data,updated_at) VALUES($1,$2,now()) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data, updated_at=now()`, key, []byte(c.a.Box.Seal(data)))
	return err
}

func (c *dbCache) Delete(ctx context.Context, key string) error {
	_, err := c.a.St.DB.Exec(ctx, `DELETE FROM acme_cache WHERE key=$1`, key)
	return err
}
