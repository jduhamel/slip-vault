// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"testing"

	"github.com/ohler55/slip"
	"github.com/ohler55/slip/sliptest"
)

func TestKvListHappyPathContainsChildKeys(t *testing.T) {
	scope := connectedScope(t)
	prefix := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (let ((keys (send v :kv-list %q %q)))
                                 (list (and (member "one" keys :test 'equal) t)
                                       (and (member "two" keys :test 'equal) t))))`,
			kvMount, prefix+"/one", kvMount, prefix+"/two", kvMount, prefix),
		Expect: `(t t)`,
	}).Test(t)
}

func TestKvListValuesAreNotSecretObjects(t *testing.T) {
	scope := connectedScope(t)
	prefix := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (let ((first (car (send v :kv-list %q %q))))
                                 (list (stringp first) (secretp first))))`,
			kvMount, prefix+"/one", kvMount, prefix),
		Expect: `(t nil)`,
	}).Test(t)
}

func TestKvListEmptyPrefixIsFalsy(t *testing.T) {
	scope := connectedScope(t)
	prefix := uniquePath(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: fmt.Sprintf(`(and (send v :kv-list %q %q) t)`, kvMount, prefix),
		Expect: `nil`,
	}).Test(t)
}

func TestKvListArgTypeErrorMount(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    `(send v :kv-list 123 "whatever")`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestKvListArgTypeErrorPath(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    fmt.Sprintf(`(send v :kv-list %q 456)`, kvMount),
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestVaultKvListFlosFunction(t *testing.T) {
	scope := connectedScope(t)
	prefix := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (vault-kv-put v %q %q (list (cons "pw" "hunter2")))
                               (and (member "one" (vault-kv-list v %q %q) :test 'equal) t))`,
			kvMount, prefix+"/one", kvMount, prefix),
		Expect: `t`,
	}).Test(t)
}
