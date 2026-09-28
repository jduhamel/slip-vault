// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

var (
	clientFlavor *flavors.Flavor
)

func defClient() {
	keywords := make(slip.List, 0, len(conOptMap)+1)
	keywords = append(keywords, slip.Symbol(":init-keywords"))
	for k := range conOptMap {
		keywords = append(keywords, slip.Symbol(k))
	}
	clientFlavor = flavors.DefFlavor("vault-client",
		map[string]slip.Object{},
		[]string{},
		slip.List{
			slip.List{
				slip.Symbol(":documentation"),
				slip.String(`Is a connection to a HashiCorp Vault or OpenBao server.`),
			},
			keywords,
		},
		&Pkg,
	)
	clientFlavor.DefMethod(":init", "", clientInitCaller{})

	clientFlavor.DefMethod(":close", "", closeCaller{})
	flavors.FlosFun("vault-close", ":close", closeCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":kv-get", "", kvGetCaller{})
	flavors.FlosFun("vault-kv-get", ":kv-get", kvGetCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":kv-get-field", "", kvGetFieldCaller{})
	flavors.FlosFun("vault-kv-get-field", ":kv-get-field", kvGetFieldCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":kv-put", "", kvPutCaller{})
	flavors.FlosFun("vault-kv-put", ":kv-put", kvPutCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":kv-patch", "", kvPatchCaller{})
	flavors.FlosFun("vault-kv-patch", ":kv-patch", kvPatchCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":kv-delete", "", kvDeleteCaller{})
	flavors.FlosFun("vault-kv-delete", ":kv-delete", kvDeleteCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":kv-list", "", kvListCaller{})
	flavors.FlosFun("vault-kv-list", ":kv-list", kvListCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":kv-metadata", "", kvMetadataCaller{})
	flavors.FlosFun("vault-kv-metadata", ":kv-metadata", kvMetadataCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":read", "", readCaller{})
	flavors.FlosFun("vault-read", ":read", readCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":write", "", writeCaller{})
	flavors.FlosFun("vault-write", ":write", writeCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":token-lookup-self", "", tokenLookupSelfCaller{})
	flavors.FlosFun("vault-token-lookup-self", ":token-lookup-self", tokenLookupSelfCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":token-renew-self", "", tokenRenewSelfCaller{})
	flavors.FlosFun("vault-token-renew-self", ":token-renew-self", tokenRenewSelfCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":token", "", tokenCaller{})
	flavors.FlosFun("vault-token", ":token", tokenCaller{}.FuncDocs(), &Pkg)

	clientFlavor.DefMethod(":renewal-status", "", renewalStatusCaller{})
	flavors.FlosFun("vault-renewal-status", ":renewal-status", renewalStatusCaller{}.FuncDocs(), &Pkg)
}

// Client is a container for the elements needed by an instance of the
// vault-client flavor. The connect options are not kept since they include
// the token, except for the AppRole credentials which are kept when
// auto-renew is on so a new login can be made at the token's max ttl.
type Client struct {
	api       *api.Client
	closed    atomic.Bool
	autoRenew bool
	renewable bool
	revoke    bool     // the token came from a login and is revoked on close
	increment int      // renew increment in seconds
	approle   []string // role-id, secret-id, mount

	cancel context.CancelFunc // stops the renewal watcher
	wg     sync.WaitGroup

	mu          sync.Mutex
	lastRenewal time.Time
	renewErr    error
}

// API returns the underlying Vault API client or nil if the client has been
// closed.
func (c *Client) API() *api.Client {
	if c.closed.Load() {
		return nil
	}
	return c.api
}

// renewStatus returns the time of the last renewal and the error, if any,
// that stopped the renewals.
func (c *Client) renewStatus() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastRenewal, c.renewErr
}

// login logs in with the AppRole credentials and returns the auth.
func (c *Client) login(ctx context.Context) (*api.SecretAuth, error) {
	secret, err := c.api.Logical().WriteWithContext(ctx, "auth/"+c.approle[2]+"/login", map[string]any{
		"role_id":   c.approle[0],
		"secret_id": c.approle[1],
	})
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Auth == nil || len(secret.Auth.ClientToken) == 0 {
		return nil, errors.New("approle login did not return a token")
	}
	return secret.Auth, nil
}

// startWatcher starts renewing the token described by auth in the
// background.
func (c *Client) startWatcher(auth *api.SecretAuth) {
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.wg.Add(1)
	go c.watch(ctx, auth)
}

// watch renews the token until it can no longer be renewed. An AppRole token
// is then replaced by a new login and watched in turn. For other tokens, or
// if the login fails, the error is stored and raised by later method calls.
func (c *Client) watch(ctx context.Context, auth *api.SecretAuth) {
	defer c.wg.Done()
	for {
		err := c.watchToken(ctx, auth)
		if ctx.Err() != nil {
			return
		}
		if c.approle == nil {
			if err == nil {
				err = errors.New("max ttl reached")
			}
			c.mu.Lock()
			c.renewErr = err
			c.mu.Unlock()
			return
		}
		auth, err = c.login(ctx)
		if ctx.Err() != nil {
			// Closed while logging in. The new token is never used so
			// revoke it rather than leave it alive until its ttl expires.
			if err == nil && auth != nil {
				c.revokeToken(auth.ClientToken)
			}
			return
		}
		c.mu.Lock()
		if err != nil {
			c.renewErr = err
		} else {
			c.api.SetToken(auth.ClientToken)
			c.lastRenewal = time.Now().UTC()
		}
		c.mu.Unlock()
		if err != nil {
			return
		}
	}
}

// watchToken runs a lifetime watcher on the token until ctx is done or the
// watcher stops. The watcher's error, nil if it stopped at the max ttl, is
// returned.
func (c *Client) watchToken(ctx context.Context, auth *api.SecretAuth) error {
	w, err := c.api.NewLifetimeWatcher(&api.LifetimeWatcherInput{
		Secret:    &api.Secret{Auth: auth},
		Increment: c.increment,
	})
	if err != nil {
		return err
	}
	go w.Start()
	defer w.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case r := <-w.RenewCh():
			c.mu.Lock()
			c.lastRenewal = r.RenewedAt
			c.mu.Unlock()
		case err = <-w.DoneCh():
			return err
		}
	}
}

// close stops the renewal watcher, revokes a token from a login, and clears
// the token. Closing more than once does nothing.
func (c *Client) close() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	if c.revoke {
		ctx, cf := context.WithTimeout(context.Background(), 5*time.Second)
		// Errors are ignored since the token is cleared either way.
		_ = c.api.Auth().Token().RevokeSelfWithContext(ctx, "")
		cf()
	}
	c.api.ClearToken()
}

// selfClient returns the Client of the self instance and raises an error if
// the client has been closed.
func selfClient(s *slip.Scope, depth int) *Client {
	self := s.Get("self").(*flavors.Instance)
	c, ok := self.Any.(*Client)
	if !ok || c.closed.Load() {
		slip.ErrorPanic(s, depth, "vault-client is closed")
	}
	return c
}

// selfAPI returns the API client of the self instance and raises an error if
// the client has been closed or its token could not be kept alive.
func selfAPI(s *slip.Scope, depth int) *api.Client {
	c := selfClient(s, depth)
	if _, err := c.renewStatus(); err != nil {
		slip.ErrorPanic(s, depth, "vault token expired: %s", err)
	}
	return c.api
}

// revokeToken revokes token, typically one obtained by a login that will
// never be used. Errors are ignored since this is best effort cleanup.
func (c *Client) revokeToken(token string) {
	rc, err := c.api.Clone()
	if err != nil {
		return
	}
	rc.SetToken(token)
	ctx, cf := context.WithTimeout(context.Background(), 5*time.Second)
	defer cf()
	_ = rc.Auth().Token().RevokeSelfWithContext(ctx, "")
}
