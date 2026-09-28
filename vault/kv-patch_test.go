// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"testing"

	"github.com/ohler55/slip"
	"github.com/ohler55/slip/sliptest"
)

func TestKvPatchHappyPathAddsAndKeepsFields(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "a" "1")))
                               (send v :kv-patch %q %q (list (cons "b" "2")))
                               (let ((got (send v :kv-get %q %q)))
                                 (list (secret-value (cdr (assoc "a" got)))
                                       (secret-value (cdr (assoc "b" got))))))`,
			kvMount, path, kvMount, path, kvMount, path),
		Expect: `("1" "2")`,
	}).Test(t)
}

func TestKvPatchOverwritesExistingField(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "a" "1")))
                               (send v :kv-patch %q %q (list (cons "a" "updated")))
                               (secret-value (cdr (assoc "a" (send v :kv-get %q %q)))))`,
			kvMount, path, kvMount, path, kvMount, path),
		Expect: `"updated"`,
	}).Test(t)
}

func TestKvPatchReturnsTruthyVersionMetadata(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "a" "1")))
                               (and (send v :kv-patch %q %q (list (cons "b" "2"))) t))`,
			kvMount, path, kvMount, path),
		Expect: `t`,
	}).Test(t)
}

func TestKvPatchOnMissingPathErrors(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: fmt.Sprintf(`(send v :kv-patch %q %q (list (cons "a" "1")))`, kvMount, path),
		Panics: true,
	}).Test(t)
}

func TestKvPatchArgTypeErrorData(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "a" "1")))
                               (send v :kv-patch %q %q 42))`,
			kvMount, path, kvMount, path),
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestKvPatchArgTypeErrorMount(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    `(send v :kv-patch t "whatever" (list (cons "a" "1")))`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestVaultKvPatchFlosFunction(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (vault-kv-put v %q %q (list (cons "a" "1")))
                               (vault-kv-patch v %q %q (list (cons "b" "2")))
                               (secret-value (cdr (assoc "b" (vault-kv-get v %q %q)))))`,
			kvMount, path, kvMount, path, kvMount, path),
		Expect: `"2"`,
	}).Test(t)
}
