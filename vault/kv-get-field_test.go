// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"testing"

	"github.com/ohler55/slip"
	"github.com/ohler55/slip/sliptest"
)

func TestKvGetFieldHappyPath(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (secret-value (send v :kv-get-field %q %q "pw")))`,
			kvMount, path, kvMount, path),
		Expect: `"hunter2"`,
	}).Test(t)
}

func TestKvGetFieldReturnsASecretObject(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (secretp (send v :kv-get-field %q %q "pw")))`,
			kvMount, path, kvMount, path),
		Expect: `t`,
	}).Test(t)
}

func TestKvGetFieldMissingPathReturnsNil(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: fmt.Sprintf(`(send v :kv-get-field %q %q "pw")`, kvMount, path),
		Expect: `nil`,
	}).Test(t)
}

func TestKvGetFieldMissingFieldReturnsNil(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (send v :kv-get-field %q %q "does-not-exist"))`,
			kvMount, path, kvMount, path),
		Expect: `nil`,
	}).Test(t)
}

func TestKvGetFieldSpecificVersion(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "first")))
                               (send v :kv-put %q %q (list (cons "pw" "second")))
                               (secret-value (send v :kv-get-field %q %q "pw" :version 1)))`,
			kvMount, path, kvMount, path, kvMount, path),
		Expect: `"first"`,
	}).Test(t)
}

func TestKvGetFieldArgTypeErrorField(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    fmt.Sprintf(`(send v :kv-get-field %q %q 789)`, kvMount, path),
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestKvGetFieldArgTypeErrorPath(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    fmt.Sprintf(`(send v :kv-get-field %q 456 "pw")`, kvMount),
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestVaultKvGetFieldFlosFunction(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (vault-kv-put v %q %q (list (cons "pw" "hunter2")))
                               (secret-value (vault-kv-get-field v %q %q "pw")))`,
			kvMount, path, kvMount, path),
		Expect: `"hunter2"`,
	}).Test(t)
}
