// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ohler55/slip"
	"github.com/ohler55/slip/sliptest"
)

// :read and :write are the generic escape hatches for engines other than
// KV. To keep these tests independent of any speculative response shape,
// they exercise three builtin, well-documented Vault endpoints rather than
// the KV engine: auth/token/lookup-self and sys/tools/hash (data-only
// responses), and auth/token/create (an auth response), all of which are
// always mounted on a dev server.
//
// The response is an alist with entries :data, :lease-id, :lease-duration,
// :renewable, and (only when the backend returned auth info) :auth - see
// responseAlist in read.go. The keys are keyword symbols, so assoc is used
// with a bare :keyword rather than a string.

func TestReadWrapsResponseDataAsSecrets(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope: scope,
		Source: `(secretp (cdr (assoc "id"
                       (cdr (assoc :data (send v :read "auth/token/lookup-self"))))))`,
		Expect: `t`,
	}).Test(t)
}

func TestReadTokenIDMatchesConnectedToken(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope: scope,
		Source: `(secret-value (cdr (assoc "id"
                       (cdr (assoc :data (send v :read "auth/token/lookup-self"))))))`,
		Expect: fmt.Sprintf("%q", rootToken),
	}).Test(t)
}

func TestReadMissingPathReturnsNil(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: `(send v :read "secret/data/definitely-does-not-exist-anywhere")`,
		Expect: `nil`,
	}).Test(t)
}

func TestReadArgTypeErrorPath(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    `(send v :read 123)`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

// TestReadArgTypeErrorDoesNotLeakValue covers the review item that a
// bad-typed argument's error message names only the type, never the value.
// This is currently a real gap, not just an unimplemented feature: :read's
// path argument is checked with the framework's generic slip.MustBeString
// (via trimPath), which embeds the offending value's printed form in the
// message (see slip/type-error.go TypeErrorNew), unlike util.go's
// redactedTypePanic used for :token, :approle, and data map values. The same
// gap likely applies to every mount/path/field argument across the kv-*
// methods, since they all go through trimPath or slip.MustBeString directly.
func TestReadArgTypeErrorDoesNotLeakValue(t *testing.T) {
	scope := connectedScope(t)
	canary := randomCanary(t, "sekrit-")
	scope.Let(slip.Symbol("canary"), slip.String(canary))
	msg := panicMessage(t, scope, `(send v :read (list canary))`)
	if strings.Contains(msg, canary) {
		t.Fatalf(":read's arg type error leaked a bad-typed path argument's contents: %q", msg)
	}
}

func TestWriteWrapsResponseDataAsSecrets(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope: scope,
		// base64("hello") == "aGVsbG8="; sys/tools/hash returns {"sum": "<hex>"}.
		Source: `(secretp (cdr (assoc "sum"
                       (cdr (assoc :data
                         (send v :write "sys/tools/hash" (list (cons "input" "aGVsbG8=") (cons "format" "hex"))))))))`,
		Expect: `t`,
	}).Test(t)
}

func TestWriteResponseValueIsCorrect(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope: scope,
		// sha2-256 of "hello" (the default algorithm for sys/tools/hash).
		Source: `(secret-value (cdr (assoc "sum"
                       (cdr (assoc :data
                         (send v :write "sys/tools/hash" (list (cons "input" "aGVsbG8=") (cons "format" "hex"))))))))`,
		Expect: `"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"`,
	}).Test(t)
}

func TestWriteArgTypeErrorPath(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    `(send v :write 123 (list (cons "input" "aGVsbG8=")))`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestWriteArgTypeErrorData(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    `(send v :write "sys/tools/hash" "not-an-alist-or-hash-table")`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

// TestWriteAuthTokenCreateWrapsClientTokenAsSecret covers the review item
// that :write against an auth-producing endpoint (auth/token/create) exposes
// the new token as a secret, under the :auth entry of the shared
// responseAlist shape (see read.go).
func TestWriteAuthTokenCreateWrapsClientTokenAsSecret(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope: scope,
		Source: `(secretp (cdr (assoc :client-token
                       (cdr (assoc :auth (send v :write "auth/token/create" nil))))))`,
		Expect: `t`,
	}).Test(t)
}

// TestWriteAuthTokenCreateClientTokenIsUsable confirms the wrapped token is
// the real, usable token, not a placeholder: a fresh client built from it
// via secret-value can look itself up.
func TestWriteAuthTokenCreateClientTokenIsUsable(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(let* ((resp (send v :write "auth/token/create" nil))
                       (tok (secret-value (cdr (assoc :client-token (cdr (assoc :auth resp))))))
                       (v2 (vault-connect :address %q :token tok)))
                   (and (send v2 :token-lookup-self) t))`, vaultAddrURL()),
		Expect: `t`,
	}).Test(t)
}

func TestVaultReadFlosFunction(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope: scope,
		Source: `(secretp (cdr (assoc "id"
                       (cdr (assoc :data (vault-read v "auth/token/lookup-self"))))))`,
		Expect: `t`,
	}).Test(t)
}

func TestVaultWriteFlosFunction(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope: scope,
		Source: `(secretp (cdr (assoc "sum"
                       (cdr (assoc :data
                         (vault-write v "sys/tools/hash" (list (cons "input" "aGVsbG8=") (cons "format" "hex"))))))))`,
		Expect: `t`,
	}).Test(t)
}
