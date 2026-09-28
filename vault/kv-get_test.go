// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"testing"

	"github.com/ohler55/slip"
	"github.com/ohler55/slip/sliptest"
)

func TestKvGetHappyPath(t *testing.T) {
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

func TestKvGetValueIsASecretObject(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (secretp (cdr (assoc "pw" (send v :kv-get %q %q)))))`,
			kvMount, path, kvMount, path),
		Expect: `t`,
	}).Test(t)
}

func TestKvGetMissingPathReturnsNil(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: fmt.Sprintf(`(send v :kv-get %q %q)`, kvMount, path),
		Expect: `nil`,
	}).Test(t)
}

func TestKvGetSpecificVersion(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "first")))
                               (send v :kv-put %q %q (list (cons "pw" "second")))
                               (secret-value (cdr (assoc "pw" (send v :kv-get %q %q :version 1)))))`,
			kvMount, path, kvMount, path, kvMount, path),
		Expect: `"first"`,
	}).Test(t)
}

func TestKvGetDefaultVersionIsLatest(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "first")))
                               (send v :kv-put %q %q (list (cons "pw" "second")))
                               (secret-value (cdr (assoc "pw" (send v :kv-get %q %q)))))`,
			kvMount, path, kvMount, path, kvMount, path),
		Expect: `"second"`,
	}).Test(t)
}

func TestKvGetArgTypeErrorMount(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    `(send v :kv-get 123 "whatever")`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestKvGetArgTypeErrorPath(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    fmt.Sprintf(`(send v :kv-get %q 456)`, kvMount),
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestKvGetVersionWrongTypeIsTypeError(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    fmt.Sprintf(`(send v :kv-get %q %q :version "not-a-number")`, kvMount, path),
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestKvGetTimeoutAccepted(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (and (send v :kv-get %q %q :timeout 5) t))`,
			kvMount, path, kvMount, path),
		Expect: `t`,
	}).Test(t)
}

func TestVaultKvGetFlosFunction(t *testing.T) {
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
