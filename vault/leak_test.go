// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ohler55/slip"
	"github.com/ohler55/slip/sliptest"
)

// TestKvPutGetPrintedResultNeverLeaksPlaintext is the leak test called for
// in the spec: put a unique plaintext, get it back, and confirm the
// plaintext never appears in the printed representation of the result -
// only an explicit secret-value call should reveal it.
func TestKvPutGetPrintedResultNeverLeaksPlaintext(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	plaintext := fmt.Sprintf("hunter2-%d", time.Now().UnixNano())

	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" %q)))
                               (send v :kv-get %q %q))`,
			kvMount, path, plaintext, kvMount, path),
		Readably: true,
		Validate: func(t *testing.T, result slip.Object) {
			printed := slip.ObjectString(result)
			if strings.Contains(printed, plaintext) {
				t.Fatalf("kv-get's printed result leaked the plaintext %q: %s", plaintext, printed)
			}
			if !strings.Contains(printed, "#<secret>") {
				t.Fatalf("kv-get's printed result did not redact the value at all: %s", printed)
			}
		},
	}).Test(t)

	// Sanity check: the plaintext really is retrievable via the one
	// sanctioned escape hatch, secret-value, so the redaction above isn't
	// hiding a bug where the value was never stored correctly.
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(secret-value (cdr (assoc "pw" (send v :kv-get %q %q))))`,
			kvMount, path),
		Expect: fmt.Sprintf("%q", plaintext),
	}).Test(t)
}

// TestKvGetFieldPrintedResultNeverLeaksPlaintext repeats the same check for
// the single-field accessor.
func TestKvGetFieldPrintedResultNeverLeaksPlaintext(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	plaintext := fmt.Sprintf("hunter2-%d", time.Now().UnixNano())

	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" %q)))
                               (send v :kv-get-field %q %q "pw"))`,
			kvMount, path, plaintext, kvMount, path),
		Validate: func(t *testing.T, result slip.Object) {
			printed := slip.ObjectString(result)
			if strings.Contains(printed, plaintext) {
				t.Fatalf("kv-get-field's printed result leaked the plaintext %q: %s", plaintext, printed)
			}
			if !strings.Contains(printed, "#<secret>") {
				t.Fatalf("expected kv-get-field to return a #<secret>, got: %s", printed)
			}
		},
	}).Test(t)
}

// TestTokenLookupSelfDoesNotLeakTokenValue checks that describing or
// printing the whole token-lookup-self response never exposes the raw
// token string, even though the token itself is separately obtainable via
// (secret-value (send v :token)). It uses an approle-issued token (a
// random accessor value) rather than the dev root token, because "root"
// is also the dev server's policy name and would appear in the response
// legitimately, making it a useless needle to search for.
func TestTokenLookupSelfDoesNotLeakTokenValue(t *testing.T) {
	requireApprole(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(let* ((v (vault-connect :address %q :approle (list %q %q)))
                                     (tok (secret-value (send v :token))))
                               (search tok (format nil "~s" (send v :token-lookup-self))))`,
			vaultAddrURL(), approleRoleID, approleSecretID),
		Expect: `nil`,
	}).Test(t)
}

// TestNumericOptionTypeErrorsNeverLeakValue checks that a plaintext put in a
// numeric keyword slot by mistake is not echoed in the type error.
func TestNumericOptionTypeErrorsNeverLeakValue(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	for _, form := range []string{
		`(vault-connect :address %[2]q :token "x" :timeout %[1]q)`,
		`(vault-connect :address %[2]q :token "x" :renew-increment %[1]q)`,
		`(send v :kv-get "secret" %[3]q :version %[1]q)`,
		`(send v :kv-put "secret" %[3]q '(("k" . "v")) :cas %[1]q)`,
		`(send v :kv-delete "secret" %[3]q :versions %[1]q)`,
		`(send v :kv-delete "secret" %[3]q :versions (list %[1]q))`,
		`(send v :token-renew-self :increment %[1]q)`,
	} {
		canary := randomCanary(t, "numeric")
		src := fmt.Sprintf(form, canary, vaultAddrURL(), path)
		msg := panicMessage(t, scope, src)
		if msg == "" {
			t.Fatalf("expected a type error from %s", src)
		}
		if strings.Contains(msg, canary) {
			t.Fatalf("type error leaked the value: %s", msg)
		}
	}
}
