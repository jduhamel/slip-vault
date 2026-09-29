// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ohler55/slip"
	"github.com/ohler55/slip/sliptest"
)

func TestKvPutHappyPathAlist(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (secret-value (cdr (assoc "pw" (send v :kv-get %q %q)))))`,
			kvMount, path, kvMount, path),
		Expect: `"hunter2"`,
	}).Test(t)
}

func TestKvPutHappyPathHashTable(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(let ((data (make-hash-table)))
                               (setf (gethash "pw" data) "hunter2")
                               (send v :kv-put %q %q data)
                               (secret-value (cdr (assoc "pw" (send v :kv-get %q %q)))))`,
			kvMount, path, kvMount, path),
		Expect: `"hunter2"`,
	}).Test(t)
}

func TestKvPutSecretObjectAsValueIsUnwrapped(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" (make-secret "hunter2"))))
                               (secret-value (cdr (assoc "pw" (send v :kv-get %q %q)))))`,
			kvMount, path, kvMount, path),
		Expect: `"hunter2"`,
	}).Test(t)
}

// --- non-string values --------------------------------------------------
//
// secretObject (secret.go) wraps strings as is, and everything else as its
// JSON encoding, so a round trip through Vault must come back as the JSON
// text of the original value, not the string form. json.Marshal produces
// identical text for a Go float64(42) or json.Number("42") here, so the
// expectation is stable regardless of how the Vault client decodes numbers.

func TestKvPutNumberValueRoundtripsAsJSONText(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "n" 42)))
                               (secret-value (cdr (assoc "n" (send v :kv-get %q %q)))))`,
			kvMount, path, kvMount, path),
		Expect: `"42"`,
	}).Test(t)
}

func TestKvPutBoolValueRoundtripsAsJSONText(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "b" t)))
                               (secret-value (cdr (assoc "b" (send v :kv-get %q %q)))))`,
			kvMount, path, kvMount, path),
		Expect: `"true"`,
	}).Test(t)
}

func TestKvPutNestedObjectValueRoundtripsAsJSONText(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (let ((nested (make-hash-table)))
                                 (setf (gethash "a" nested) "1")
                                 (send v :kv-put %q %q (list (cons "obj" nested))))
                               (secret-value (cdr (assoc "obj" (send v :kv-get %q %q)))))`,
			kvMount, path, kvMount, path),
		Readably: true, // so embedded quotes in the JSON text are escaped in the printed form
		Expect:   `"{\"a\":\"1\"}"`,
	}).Test(t)
}

// TestKvPutArrayValueRoundtripsAsJSONText covers toVaultValue's plain-list
// (non-alist) branch. The list is stored as a hash-table value (rather than
// via cons at the top level) because (cons "key" a-list) prepends "key" onto
// the list instead of pairing with it - cons only forms a genuine (key .
// value) pair when the second argument is not itself a list (see cl/cons.go:
// "prepends object-1 to object-2 if object-2 is a list").
func TestKvPutArrayValueRoundtripsAsJSONText(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (let ((h (make-hash-table)))
                                 (setf (gethash "arr" h) (list "a" "b" "c"))
                                 (send v :kv-put %q %q (list (cons "wrapper" h))))
                               (secret-value (cdr (assoc "wrapper" (send v :kv-get %q %q)))))`,
			kvMount, path, kvMount, path),
		Readably: true,
		Expect:   `"{\"arr\":[\"a\",\"b\",\"c\"]}"`,
	}).Test(t)
}

// TestKvPutNestedAlistValueWithSymbolKeyRoundtripsAsJSONText covers a value
// that is itself a (key . value) alist (not a hash-table) with a symbol key
// rather than a string key - the isAlist/vaultKey Symbol branches in
// util.go's toVaultValue. As above, the alist is stored as a hash-table
// value to avoid cons's list-prepending behavior at the top level.
func TestKvPutNestedAlistValueWithSymbolKeyRoundtripsAsJSONText(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (let ((h (make-hash-table)))
                                 (setf (gethash "obj" h) (list (cons 'a "1")))
                                 (send v :kv-put %q %q (list (cons "wrapper" h))))
                               (secret-value (cdr (assoc "wrapper" (send v :kv-get %q %q)))))`,
			kvMount, path, kvMount, path),
		Readably: true,
		Expect:   `"{\"obj\":{\"a\":\"1\"}}"`,
	}).Test(t)
}

// --- mount/path slash normalization --------------------------------------

// TestKvPutGetMountAndPathTrailingSlashesAreEquivalent covers the review
// item that mount "secret/" with path "/a/b/" behaves the same as mount
// "secret" with path "a/b".
func TestKvPutGetMountAndPathTrailingSlashesAreEquivalent(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (secret-value (cdr (assoc "pw" (send v :kv-get "secret/" %q)))))`,
			kvMount, path, "/"+path+"/"),
		Expect: `"hunter2"`,
	}).Test(t)
}

func TestKvPutMultipleKeys(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "user" "alice") (cons "pw" "hunter2")))
                               (let ((got (send v :kv-get %q %q)))
                                 (list (secret-value (cdr (assoc "user" got)))
                                       (secret-value (cdr (assoc "pw" got))))))`,
			kvMount, path, kvMount, path),
		Expect: `("alice" "hunter2")`,
	}).Test(t)
}

func TestKvPutReturnsTruthyVersionMetadata(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(and (send v :kv-put %q %q (list (cons "pw" "hunter2"))) t)`,
			kvMount, path),
		Expect: `t`,
	}).Test(t)
}

func TestKvPutCasZeroAllowsInitialCreate(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(and (send v :kv-put %q %q (list (cons "pw" "hunter2")) :cas 0) t)`,
			kvMount, path),
		Expect: `t`,
	}).Test(t)
}

func TestKvPutCasConflictOnExistingVersion(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	// First put with :cas 0 creates version 1. A second :cas 0 put requires
	// the path to not yet exist, so it must conflict.
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "first")) :cas 0)
                               (send v :kv-put %q %q (list (cons "pw" "second")) :cas 0))`,
			kvMount, path, kvMount, path),
		Panics: true,
	}).Test(t)
}

func TestKvPutArgTypeErrorMount(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    `(send v :kv-put 123 "whatever" (list (cons "pw" "hunter2")))`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestKvPutArgTypeErrorPath(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    fmt.Sprintf(`(send v :kv-put %q 456 (list (cons "pw" "hunter2")))`, kvMount),
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestKvPutArgTypeErrorData(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    fmt.Sprintf(`(send v :kv-put %q %q "not-an-alist-or-hash-table")`, kvMount, path),
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

// TestKvPutArgTypeErrorDataDoesNotLeakValue covers the review item that a
// bad-typed argument's error names only the type, never the value: passing
// a secret-shaped string directly as the whole data argument (instead of a
// list/hash-table) is itself a type error, and that string must not appear
// in the resulting message.
func TestKvPutArgTypeErrorDataDoesNotLeakValue(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	canary := randomCanary(t, "sekrit-")
	scope.Let(slip.Symbol("canary"), slip.String(canary))
	msg := panicMessage(t, scope, fmt.Sprintf(`(send v :kv-put %q %q canary)`, kvMount, path))
	if strings.Contains(msg, canary) {
		t.Fatalf(":kv-put's data type error leaked the bad-typed argument's contents: %q", msg)
	}
}

func TestKvPutTimeoutAccepted(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(and (send v :kv-put %q %q (list (cons "pw" "hunter2")) :timeout 5) t)`,
			kvMount, path),
		Expect: `t`,
	}).Test(t)
}

func TestVaultKvPutFlosFunction(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (vault-kv-put v %q %q (list (cons "pw" "hunter2")))
                               (secret-value (cdr (assoc "pw" (vault-kv-get v %q %q)))))`,
			kvMount, path, kvMount, path),
		Expect: `"hunter2"`,
	}).Test(t)
}
