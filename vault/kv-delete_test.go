// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"testing"

	"github.com/ohler55/slip"
	"github.com/ohler55/slip/sliptest"
)

func TestKvDeleteReturnsNil(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (send v :kv-delete %q %q))`,
			kvMount, path, kvMount, path),
		Expect: `nil`,
	}).Test(t)
}

func TestKvDeleteHappyPathRemovesLatestVersion(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (send v :kv-delete %q %q)
                               (send v :kv-get %q %q))`,
			kvMount, path, kvMount, path, kvMount, path),
		Expect: `nil`,
	}).Test(t)
}

func TestKvDeleteOnMissingPathDoesNotPanic(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: fmt.Sprintf(`(send v :kv-delete %q %q)`, kvMount, path),
		Expect: `nil`,
	}).Test(t)
}

func TestKvDeleteSpecificVersions(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "first")))
                               (send v :kv-put %q %q (list (cons "pw" "second")))
                               (send v :kv-delete %q %q :versions (list 1))
                               (secret-value (cdr (assoc "pw" (send v :kv-get %q %q :version 2)))))`,
			kvMount, path, kvMount, path, kvMount, path, kvMount, path),
		Expect: `"second"`,
	}).Test(t)
}

func TestKvDeleteArgTypeErrorMount(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    `(send v :kv-delete 123 "whatever")`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestKvDeleteArgTypeErrorPath(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    fmt.Sprintf(`(send v :kv-delete %q 456)`, kvMount),
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestVaultKvDeleteFlosFunction(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (vault-kv-put v %q %q (list (cons "pw" "hunter2")))
                               (vault-kv-delete v %q %q)
                               (vault-kv-get v %q %q))`,
			kvMount, path, kvMount, path, kvMount, path),
		Expect: `nil`,
	}).Test(t)
}
