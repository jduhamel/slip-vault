// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ohler55/slip"
	"github.com/ohler55/slip/sliptest"
)

// approleConnectedScope returns a Scope with "v" bound to a vault-client
// logged in via the given approle role-id/secret-id, plus any extra
// vault-connect keyword arguments appended verbatim (e.g. ":auto-renew
// nil"). Mirrors connectedScope in main_test.go but for approle logins,
// which the auto-renew tests need in order to get a renewable token.
func approleConnectedScope(t *testing.T, roleID, secretID, extraKeywords string) *slip.Scope {
	t.Helper()
	scope := slip.NewScope()
	scope.Let(slip.Symbol("v"), nil)
	src := fmt.Sprintf(`(setq v (vault-connect :address %q :approle (list %q %q) %s))`,
		vaultAddrURL(), roleID, secretID, extraKeywords)
	result := slip.ReadString(src, scope).Eval(scope, nil)
	if result == nil {
		t.Fatalf("vault-connect returned nil for %s", src)
	}
	return scope
}

// TestRenewalStatusDefaultsForApproleLogin is a fast (no sleeping) sanity
// check of :renewal-status right after an approle login, using the normal
// (1h ttl) role so it does not compete for wall time with the short-TTL
// tests below.
func TestRenewalStatusDefaultsForApproleLogin(t *testing.T) {
	requireApprole(t)
	scope := approleConnectedScope(t, approleRoleID, approleSecretID, "")
	(&sliptest.Function{
		Scope:  scope,
		Source: `(getf (send v :renewal-status) :auto-renew)`,
		Expect: `t`,
	}).Test(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(getf (send v :renewal-status) :renewable)`,
		Expect: `t`,
	}).Test(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(getf (send v :renewal-status) :error)`,
		Expect: `nil`,
	}).Test(t)
}

func TestVaultRenewalStatusFlosFunction(t *testing.T) {
	requireApprole(t)
	scope := approleConnectedScope(t, approleRoleID, approleSecretID, "")
	(&sliptest.Function{
		Scope:  scope,
		Source: `(getf (vault-renewal-status v) :auto-renew)`,
		Expect: `t`,
	}).Test(t)
}

// TestAutoRenewKeepsTokenAliveAcrossTTL is spec Test A: token_ttl=4s,
// token_max_ttl=10s. After sleeping past the ttl (but under the max ttl),
// the token must still work because the LifetimeWatcher renewed it, and
// :renewal-status must show a non-nil :last-renewal.
func TestAutoRenewKeepsTokenAliveAcrossTTL(t *testing.T) {
	t.Parallel()
	requireShortApprole(t)
	scope := approleConnectedScope(t, approleShortRoleID, approleShortSecretID, "")

	time.Sleep(6 * time.Second)

	(&sliptest.Function{
		Scope:  scope,
		Source: `(and (send v :token-lookup-self) t)`,
		Expect: `t`,
	}).Test(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(getf (send v :renewal-status) :renewable)`,
		Expect: `t`,
	}).Test(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(and (getf (send v :renewal-status) :last-renewal) t)`,
		Expect: `t`,
	}).Test(t)
}

// TestAutoRenewReLoginsAfterMaxTTL is spec Test B: sleeping past the
// token_max_ttl (10s) must trigger a fresh approle login (the watcher's
// DoneCh path) rather than leaving the client stuck with an expired token.
func TestAutoRenewReLoginsAfterMaxTTL(t *testing.T) {
	t.Parallel()
	requireShortApprole(t)
	scope := approleConnectedScope(t, approleShortRoleID, approleShortSecretID, "")

	var firstToken string
	(&sliptest.Function{
		Scope:  scope,
		Source: `(secret-value (send v :token))`,
		Validate: func(t *testing.T, v slip.Object) {
			ss, ok := v.(slip.String)
			if !ok {
				t.Fatalf("expected a string token, got %T", v)
			}
			firstToken = string(ss)
		},
	}).Test(t)

	time.Sleep(12 * time.Second)

	(&sliptest.Function{
		Scope:  scope,
		Source: `(and (send v :token-lookup-self) t)`,
		Expect: `t`,
	}).Test(t)
	// A fresh AppRole login, not a renewal, is what carries the client past
	// its max ttl, so the token value itself must have changed.
	(&sliptest.Function{
		Scope:  scope,
		Source: fmt.Sprintf(`(equal (secret-value (send v :token)) %q)`, firstToken),
		Expect: `nil`,
	}).Test(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(and (getf (send v :renewal-status) :last-renewal) t)`,
		Expect: `t`,
	}).Test(t)
}

// TestAutoRenewDisabledViaKeyword is spec Test C: :auto-renew nil must be
// reflected back by :renewal-status even though the token is otherwise
// renewable.
func TestAutoRenewDisabledViaKeyword(t *testing.T) {
	requireApprole(t)
	scope := approleConnectedScope(t, approleRoleID, approleSecretID, ":auto-renew nil")
	(&sliptest.Function{
		Scope:  scope,
		Source: `(getf (send v :renewal-status) :auto-renew)`,
		Expect: `nil`,
	}).Test(t)
}

// TestAutoRenewRootTokenNotRenewable is spec Test D: the dev server's root
// token is not renewable, so no watcher should be started, :renewable must
// be nil, and using the client afterward must not crash.
func TestAutoRenewRootTokenNotRenewable(t *testing.T) {
	scope := connectedScope(t) // root token
	(&sliptest.Function{
		Scope:  scope,
		Source: `(getf (send v :renewal-status) :renewable)`,
		Expect: `nil`,
	}).Test(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(and (send v :token-lookup-self) t)`,
		Expect: `t`,
	}).Test(t)
}

// TestAutoRenewNonApproleTokenErrorsAfterMaxTTL covers the watch/selfAPI
// path for a renewable token that did NOT come from an :approle login: per
// the plan, "Otherwise store the error. The next method call raises it."
// A token with an explicit_max_ttl equal to its ttl cannot be renewed at
// all, so the watcher's DoneCh fires almost immediately with no error
// (natural expiry at the max ttl), which watch() turns into a stored "max
// ttl reached" error since there is no approle to log in again with.
func TestAutoRenewNonApproleTokenErrorsAfterMaxTTL(t *testing.T) {
	scope := connectedScope(t) // root token, used only to mint the short token below
	scope.Let(slip.Symbol("shorttok"), nil)
	(&sliptest.Function{
		Scope: scope,
		Source: `(setq shorttok (secret-value (cdr (assoc :client-token (cdr (assoc :auth
                   (send v :write "auth/token/create"
                     (list (cons "ttl" "2s") (cons "explicit_max_ttl" "2s") (cons "renewable" t)))))))))`,
		Validate: func(t *testing.T, v slip.Object) {
			if v == nil {
				t.Fatal("expected a client-token string, got nil")
			}
		},
	}).Test(t)
	shortTok := scope.Get(slip.Symbol("shorttok"))

	scope2 := slip.NewScope()
	scope2.Let(slip.Symbol("v2"), nil)
	scope2.Let(slip.Symbol("shorttok"), shortTok)
	src := fmt.Sprintf(`(setq v2 (vault-connect :address %q :token shorttok))`, vaultAddrURL())
	code, provs := slip.ReadProv([]byte(src), scope2, t.Name(), nil)
	code.CompileWithProvenance(provs)
	if code.Eval(scope2, nil) == nil {
		t.Fatal("vault-connect with the short-lived token returned nil")
	}

	time.Sleep(6 * time.Second)

	(&sliptest.Function{
		Scope:  scope2,
		Source: `(and (getf (send v2 :renewal-status) :error) t)`,
		Expect: `t`,
	}).Test(t)
	msg := panicMessage(t, scope2, `(send v2 :token-lookup-self)`)
	if !strings.Contains(msg, "vault token expired") {
		t.Fatalf("expected a 'vault token expired' error once the watcher gave up, got: %q", msg)
	}
}

// TestCloseStopsRenewalWatcher is spec Test E: :close must stop the
// watcher (not merely clear the token) so that no goroutine is left running
// past the client's lifetime, and every call afterward raises "closed".
func TestCloseStopsRenewalWatcher(t *testing.T) {
	requireShortApprole(t)
	scope := approleConnectedScope(t, approleShortRoleID, approleShortSecretID, "")
	token := string(slip.ReadString(`(secret-value (send v :token))`, scope).Eval(scope, nil).(slip.String))
	(&sliptest.Function{
		Scope:  scope,
		Source: `(send v :close)`,
		Expect: `nil`,
	}).Test(t)
	msg := panicMessage(t, scope, `(send v :token-lookup-self)`)
	if !strings.Contains(msg, "closed") {
		t.Fatalf("expected a closed-client error after :close stopped the watcher, got: %q", msg)
	}
	// :close revokes a token obtained by an approle login. Watcher exit is
	// guaranteed by close waiting on the watcher's WaitGroup (see -race runs).
	if status := lookupSelfStatus(t, token); status != http.StatusForbidden {
		t.Fatalf("expected the approle token to be revoked (403) after :close, got status %d", status)
	}
}

// lookupSelfStatus returns the HTTP status of a token lookup-self with token.
func lookupSelfStatus(t *testing.T, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, vaultAddrURL()+"/v1/auth/token/lookup-self", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
