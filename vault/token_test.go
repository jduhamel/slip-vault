// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ohler55/slip/sliptest"
)

func TestTokenLookupSelfIsTruthy(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(and (send v :token-lookup-self) t)`,
		Expect: `t`,
	}).Test(t)
}

func TestTokenLookupSelfIDIsASecret(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(secretp (cdr (assoc "id" (send v :token-lookup-self))))`,
		Expect: `t`,
	}).Test(t)
}

// TestTokenLookupSelfAccessorIsASecret covers "accessor", one of the other
// two tokenFields entries (token-lookup-self.go) besides "id". "cubbyhole_id"
// is the third, but neither the root token nor an AppRole-issued token has
// one in its lookup-self response in practice (it only appears for tokens
// created via the CLI's cubbyhole-wrapped token helper), so there is no
// simple way to exercise that specific field here without adding a
// dependency on that mechanism.
func TestTokenLookupSelfAccessorIsASecret(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(secretp (cdr (assoc "accessor" (send v :token-lookup-self))))`,
		Expect: `t`,
	}).Test(t)
}

func TestTokenLookupSelfArgCountError(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(send v :token-lookup-self "unexpected-arg")`,
		Panics: true,
	}).Test(t)
}

func TestTokenRenewSelfOnApproleToken(t *testing.T) {
	requireApprole(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(let ((v (vault-connect :address %q :approle (list %q %q))))
                              (and (send v :token-renew-self) t))`,
			vaultAddrURL(), approleRoleID, approleSecretID),
		Expect: `t`,
	}).Test(t)
}

func TestTokenRenewSelfWithIncrement(t *testing.T) {
	requireApprole(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(let ((v (vault-connect :address %q :approle (list %q %q))))
                              (and (send v :token-renew-self :increment 60) t))`,
			vaultAddrURL(), approleRoleID, approleSecretID),
		Expect: `t`,
	}).Test(t)
}

func TestTokenPrintsRedacted(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(send v :token)`,
		Expect: `#<secret>`,
	}).Test(t)
}

func TestTokenValueMatchesConnectedToken(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(secret-value (send v :token))`,
		Expect: fmt.Sprintf("%q", rootToken),
	}).Test(t)
}

func TestCloseReturnsNil(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(send v :close)`,
		Expect: `nil`,
	}).Test(t)
}

func TestCloseThenCallErrors(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(let ((v (vault-connect :address %q :token %q)))
                              (send v :close)
                              (send v :token-lookup-self))`, vaultAddrURL(), rootToken),
		Panics: true,
	}).Test(t)
}

func TestCloseTwiceIsFine(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(progn (send v :close) (send v :close))`,
		Expect: `nil`,
	}).Test(t)
}

// TestCloseThenEveryMethodErrorsContainingClosed covers the review item
// that after :close, every method (not just one representative call) raises
// an error mentioning "closed". :close itself is excluded (closing an
// already-closed client is a no-op, covered by TestCloseTwiceIsFine).
func TestCloseThenEveryMethodErrorsContainingClosed(t *testing.T) {
	methods := []string{
		`(send v :kv-get "secret" "whatever")`,
		`(send v :kv-get-field "secret" "whatever" "field")`,
		`(send v :kv-put "secret" "whatever" (list (cons "pw" "x")))`,
		`(send v :kv-patch "secret" "whatever" (list (cons "pw" "x")))`,
		`(send v :kv-delete "secret" "whatever")`,
		`(send v :kv-list "secret" "whatever")`,
		`(send v :kv-metadata "secret" "whatever")`,
		`(send v :read "secret/data/whatever")`,
		`(send v :write "secret/data/whatever" (list (cons "pw" "x")))`,
		`(send v :token-lookup-self)`,
		`(send v :token-renew-self)`,
		`(send v :token)`,
	}
	for _, m := range methods {
		t.Run(m, func(t *testing.T) {
			scope := connectedScope(t)
			src := fmt.Sprintf(`(progn (send v :close) %s)`, m)
			msg := panicMessage(t, scope, src)
			if !strings.Contains(msg, "closed") {
				t.Fatalf("expected the error for %s on a closed client to mention \"closed\", got: %q", m, msg)
			}
		})
	}
}

func TestVaultTokenFlosFunction(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(vault-token v)`,
		Expect: `#<secret>`,
	}).Test(t)
}

func TestVaultCloseFlosFunction(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(progn (vault-close v) (send v :token-lookup-self))`,
		Panics: true,
	}).Test(t)
}
