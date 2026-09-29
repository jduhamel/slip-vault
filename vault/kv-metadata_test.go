// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ohler55/slip"
	"github.com/ohler55/slip/sliptest"
)

func TestKvMetadataHappyPathIsTruthy(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (and (send v :kv-metadata %q %q) t))`,
			kvMount, path, kvMount, path),
		Expect: `t`,
	}).Test(t)
}

func TestKvMetadataDoesNotContainSecretValues(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (format nil "~s" (send v :kv-metadata %q %q)))`,
			kvMount, path, kvMount, path),
		Validate: func(t *testing.T, v slip.Object) {
			ss, ok := v.(slip.String)
			if !ok {
				t.Fatalf("expected a string result, got %T (%s)", v, slip.ObjectString(v))
			}
			if strings.Contains(string(ss), "hunter2") {
				t.Fatalf("kv-metadata leaked the plaintext secret value: %q", string(ss))
			}
			if strings.Contains(string(ss), "#<secret>") {
				t.Fatalf("kv-metadata should not wrap anything as a secret, but found #<secret> in: %q", string(ss))
			}
		},
	}).Test(t)
}

func TestKvMetadataMissingPathReturnsNil(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope:  scope,
		Source: fmt.Sprintf(`(send v :kv-metadata %q %q)`, kvMount, path),
		Expect: `nil`,
	}).Test(t)
}

func TestKvMetadataArgTypeErrorMount(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    `(send v :kv-metadata 123 "whatever")`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestKvMetadataArgTypeErrorPath(t *testing.T) {
	scope := connectedScope(t)
	(&sliptest.Function{
		Scope:     scope,
		Source:    fmt.Sprintf(`(send v :kv-metadata %q 456)`, kvMount),
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestKvMetadataTimeoutAccepted(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (send v :kv-put %q %q (list (cons "pw" "hunter2")))
                               (and (send v :kv-metadata %q %q :timeout 5) t))`,
			kvMount, path, kvMount, path),
		Expect: `t`,
	}).Test(t)
}

func TestVaultKvMetadataFlosFunction(t *testing.T) {
	scope := connectedScope(t)
	path := uniquePath(t)
	(&sliptest.Function{
		Scope: scope,
		Source: fmt.Sprintf(`(progn
                               (vault-kv-put v %q %q (list (cons "pw" "hunter2")))
                               (and (vault-kv-metadata v %q %q) t))`,
			kvMount, path, kvMount, path),
		Expect: `t`,
	}).Test(t)
}
