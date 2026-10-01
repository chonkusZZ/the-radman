package manager

import (
	"context"
	"time"

	"radman/internal/crl"
)

// RefreshCRL downloads one CRL and stores it.
func (a *App) RefreshCRL(ctx context.Context, url string) error {
	now := time.Now()
	der, rl, err := crl.Fetch(url)
	if err != nil {
		a.St.DB.Exec(ctx, `INSERT INTO crl_cache(url,last_attempt,last_error) VALUES($1,$2,$3)
			ON CONFLICT(url) DO UPDATE SET last_attempt=EXCLUDED.last_attempt, last_error=EXCLUDED.last_error`, url, now, err.Error())
		return err
	}
	_, err = a.St.DB.Exec(ctx, `INSERT INTO crl_cache(url,der,this_update,next_update,fetched_at,last_attempt,last_error,revoked_count)
		VALUES($1,$2,$3,$4,$5,$5,'',$6)
		ON CONFLICT(url) DO UPDATE SET der=EXCLUDED.der, this_update=EXCLUDED.this_update, next_update=EXCLUDED.next_update,
		  fetched_at=EXCLUDED.fetched_at, last_attempt=EXCLUDED.last_attempt, last_error='', revoked_count=EXCLUDED.revoked_count`,
		url, der, rl.ThisUpdate, rl.NextUpdate, now, len(rl.RevokedCertificateEntries))
	return err
}

// crlLoop keeps CRLs fresh: every minute, refresh those past the configured interval or half their validity.
func (a *App) crlLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		a.runExclusive(ctx, lockCRL, a.crlPass)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *App) crlPass(ctx context.Context) {
	interval := time.Duration(a.General(ctx).CRLIntervalMins) * time.Minute
	rows, err := a.St.DB.Query(ctx, `SELECT DISTINCT u FROM pki_profiles, unnest(crl_urls) AS u`)
	if err != nil {
		return
	}
	var urls []string
	for rows.Next() {
		var u string
		rows.Scan(&u)
		urls = append(urls, u)
	}
	rows.Close()
	for _, u := range urls {
		var fetched, last, this, next *time.Time
		a.St.DB.QueryRow(ctx, `SELECT fetched_at, last_attempt, this_update, next_update FROM crl_cache WHERE url=$1`, u).Scan(&fetched, &last, &this, &next)
		due := fetched == nil
		if fetched != nil {
			due = time.Since(*fetched) > interval
			if this != nil && next != nil && time.Now().After(this.Add(next.Sub(*this)/2)) {
				due = true
			}
		}
		if last != nil && time.Since(*last) < 5*time.Minute && fetched == nil {
			due = false // back off on failing URLs
		}
		if due {
			if err := a.RefreshCRL(ctx, u); err != nil {
				a.Log.Printf("CRL %s: %v", u, err)
			}
		}
	}
}
