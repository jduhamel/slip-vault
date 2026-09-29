// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ohler55/slip"
	"github.com/ohler55/slip/sliptest"

	"github.com/jduhamel/slip-vault/vault"
)

// --- printing ---------------------------------------------------------

func TestSecretPrintsRedactedBare(t *testing.T) {
	(&sliptest.Function{
		Source: `(make-secret "hunter2")`,
		Expect: `#<secret>`,
	}).Test(t)
}

func TestSecretFormatTildeA(t *testing.T) {
	(&sliptest.Function{
		Source: `(format nil "~a" (make-secret "hunter2"))`,
		Expect: `"#<secret>"`,
	}).Test(t)
}

func TestSecretFormatTildeS(t *testing.T) {
	(&sliptest.Function{
		Source: `(format nil "~s" (make-secret "hunter2"))`,
		Expect: `"#<secret>"`,
	}).Test(t)
}

func TestSecretPrin1ToString(t *testing.T) {
	(&sliptest.Function{
		Source: `(prin1-to-string (make-secret "hunter2"))`,
		Expect: `"#<secret>"`,
	}).Test(t)
}

func TestSecretPrincToString(t *testing.T) {
	(&sliptest.Function{
		Source: `(princ-to-string (make-secret "hunter2"))`,
		Expect: `"#<secret>"`,
	}).Test(t)
}

func TestSecretInListPrintsRedacted(t *testing.T) {
	(&sliptest.Function{
		Source: `(list (make-secret "hunter2") 1 "abc")`,
		Expect: `(#<secret> 1 "abc")`,
	}).Test(t)
}

func TestSecretDescribeDoesNotLeakPlaintext(t *testing.T) {
	canary := randomCanary(t, "hunter2-")
	scope := slip.NewScope()
	scope.Let(slip.Symbol("canary"), slip.String(canary))
	(&sliptest.Function{
		Scope: scope,
		Source: `(let ((out (make-string-output-stream)))
                   (describe (make-secret canary) out)
                   (get-output-stream-string out))`,
		Validate: func(t *testing.T, v slip.Object) {
			ss, ok := v.(slip.String)
			if !ok {
				t.Fatalf("expected a string result, got %T (%s)", v, slip.ObjectString(v))
			}
			out := string(ss)
			if strings.Contains(out, canary) {
				t.Fatalf("describe output leaked the plaintext: %q", out)
			}
			if !strings.Contains(out, "secret") {
				t.Fatalf("describe output did not mention secret at all: %q", out)
			}
		},
	}).Test(t)
}

// TestSecretGoStringDoesNotLeakPlaintext covers the review item that
// fmt.Sprintf("%#v", secret) must never expose the plaintext. Go's %#v
// verb prints unexported struct fields by default unless the type
// implements fmt.GoStringer, so this only passes once Secret grows a
// GoString method that redacts, same as String/Append/Readably.
func TestSecretGoStringDoesNotLeakPlaintext(t *testing.T) {
	canary := randomCanary(t, "hunter2-")
	scope := slip.NewScope()
	scope.Let(slip.Symbol("canary"), slip.String(canary))
	code, provs := slip.ReadProv([]byte(`(make-secret canary)`), scope, t.Name(), nil)
	code.CompileWithProvenance(provs)
	result := code.Eval(scope, nil)
	sec, ok := result.(*vault.Secret)
	if !ok {
		t.Fatalf("expected *vault.Secret, got %T (%s)", result, slip.ObjectString(result))
	}
	out := fmt.Sprintf("%#v", sec)
	if strings.Contains(out, canary) {
		t.Fatalf("%%#v of a secret leaked the plaintext: %q", out)
	}
}

// --- secret-value round trip -------------------------------------------

func TestSecretValueRoundtrip(t *testing.T) {
	(&sliptest.Function{
		Source: `(secret-value (make-secret "hunter2"))`,
		Expect: `"hunter2"`,
	}).Test(t)
}

func TestSecretValueRoundtripEmptyString(t *testing.T) {
	(&sliptest.Function{
		Source: `(secret-value (make-secret ""))`,
		Expect: `""`,
	}).Test(t)
}

// --- secretp -------------------------------------------------------------

func TestSecretpTrueForSecret(t *testing.T) {
	(&sliptest.Function{
		Source: `(secretp (make-secret "hunter2"))`,
		Expect: `t`,
	}).Test(t)
}

func TestSecretpFalseForString(t *testing.T) {
	(&sliptest.Function{
		Source: `(secretp "hunter2")`,
		Expect: `nil`,
	}).Test(t)
}

func TestSecretpFalseForNil(t *testing.T) {
	(&sliptest.Function{
		Source: `(secretp nil)`,
		Expect: `nil`,
	}).Test(t)
}

func TestSecretpFalseForNumber(t *testing.T) {
	(&sliptest.Function{
		Source: `(secretp 42)`,
		Expect: `nil`,
	}).Test(t)
}

func TestSecretValueTypeErrorOnNonSecret(t *testing.T) {
	(&sliptest.Function{
		Source:    `(secret-value "not-a-secret")`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

// --- make-secret argument type checking ----------------------------------

// TestMakeSecretOnExistingSecretReturnsItAsIs covers make-secret's
// documented passthrough: wrapping an already-wrapped secret returns it,
// rather than double-wrapping or erroring.
func TestMakeSecretOnExistingSecretReturnsItAsIs(t *testing.T) {
	(&sliptest.Function{
		Source: `(secret-value (make-secret (make-secret "hunter2")))`,
		Expect: `"hunter2"`,
	}).Test(t)
}

func TestMakeSecretTypeErrorOnFixnum(t *testing.T) {
	(&sliptest.Function{
		Source:    `(make-secret 123)`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestMakeSecretTypeErrorOnNil(t *testing.T) {
	(&sliptest.Function{
		Source:    `(make-secret nil)`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestMakeSecretTypeErrorOnList(t *testing.T) {
	(&sliptest.Function{
		Source:    `(make-secret '("a" "b"))`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

// TestMakeSecretTypeErrorDoesNotLeakValue covers the review item that a
// bad-typed argument's error names only the type, never the value: passing
// a list containing something secret-shaped for make-secret's value (itself
// a type error, since only string/secret are accepted) must not echo that
// value into the message.
func TestMakeSecretTypeErrorDoesNotLeakValue(t *testing.T) {
	canary := randomCanary(t, "sekrit-")
	scope := slip.NewScope()
	scope.Let(slip.Symbol("canary"), slip.String(canary))
	msg := panicMessage(t, scope, `(make-secret (list canary))`)
	if strings.Contains(msg, canary) {
		t.Fatalf("make-secret's type error leaked a bad-typed argument's contents: %q", msg)
	}
}

// TestSecretValueTypeErrorDoesNotLeakValue is the same check for
// secret-value, which most plausibly receives a bare string by mistake
// instead of a secret - exactly the case where leaking the value back into
// the error would defeat the point of requiring a secret in the first
// place.
func TestSecretValueTypeErrorDoesNotLeakValue(t *testing.T) {
	canary := randomCanary(t, "sekrit-")
	scope := slip.NewScope()
	scope.Let(slip.Symbol("canary"), slip.String(canary))
	msg := panicMessage(t, scope, `(secret-value canary)`)
	if strings.Contains(msg, canary) {
		t.Fatalf("secret-value's type error leaked the plain-string argument: %q", msg)
	}
}

// TestSecretEqualFnTypeErrorDoesNotLeakValue is the same check for
// secret-equal's non-secret-argument branch.
func TestSecretEqualFnTypeErrorDoesNotLeakValue(t *testing.T) {
	canary := randomCanary(t, "sekrit-")
	scope := slip.NewScope()
	scope.Let(slip.Symbol("canary"), slip.String(canary))
	msg := panicMessage(t, scope, `(secret-equal (make-secret "x") canary)`)
	if strings.Contains(msg, canary) {
		t.Fatalf("secret-equal's type error leaked the plain-string argument: %q", msg)
	}
}

// --- Equal -------------------------------------------------------------
//
// cl equal (slip/pkg/cl/equal.go:64) only calls Object.Equal for types
// implementing VectorLike. *Secret does not implement VectorLike, so equal
// falls back to eq (pointer identity) for secrets and never reaches
// Secret.Equal at all: (equal s1 s2) is nil unless s1 and s2 are literally
// the same object, even when their values are identical. This is
// deliberate - it avoids equal doubling as a comparison oracle for secret
// values. secret-equal is the sanctioned way to compare values.

func TestSecretEqualDistinctObjectsSameValueAreNotEqual(t *testing.T) {
	(&sliptest.Function{
		Source: `(equal (make-secret "hunter2") (make-secret "hunter2"))`,
		Expect: `nil`,
	}).Test(t)
}

func TestSecretEqualDistinctObjectsSameValueReversedAreNotEqual(t *testing.T) {
	(&sliptest.Function{
		Source: `(let ((a (make-secret "hunter2")) (b (make-secret "hunter2"))) (equal b a))`,
		Expect: `nil`,
	}).Test(t)
}

func TestSecretEqualSameObjectIsEqual(t *testing.T) {
	(&sliptest.Function{
		Source: `(let ((a (make-secret "hunter2"))) (equal a a))`,
		Expect: `t`,
	}).Test(t)
}

func TestSecretEqualDifferentValue(t *testing.T) {
	(&sliptest.Function{
		Source: `(equal (make-secret "hunter2") (make-secret "other"))`,
		Expect: `nil`,
	}).Test(t)
}

func TestSecretEqualDifferentValueReversed(t *testing.T) {
	(&sliptest.Function{
		Source: `(let ((a (make-secret "hunter2")) (b (make-secret "other"))) (equal b a))`,
		Expect: `nil`,
	}).Test(t)
}

func TestSecretNotEqualToPlainString(t *testing.T) {
	(&sliptest.Function{
		Source: `(equal (make-secret "hunter2") "hunter2")`,
		Expect: `nil`,
	}).Test(t)
}

// TestSecretMethodsDirectly exercises Append, Simplify, and Eval directly.
// None of these are reachable through the Lisp-level tests above: the
// default printer uses Readably/String, not Append, for these forms, and
// nothing in this package calls Simplify or Eval on a Secret directly.
func TestSecretMethodsDirectly(t *testing.T) {
	sec := vault.NewSecret("hunter2")
	if got := string(sec.Append(nil)); got != "#<secret>" {
		t.Fatalf("Append: expected %q, got %q", "#<secret>", got)
	}
	if got := sec.Simplify(); got != "#<secret>" {
		t.Fatalf("Simplify: expected %q, got %v", "#<secret>", got)
	}
	if got := sec.Eval(nil, 0); got != slip.Object(sec) {
		t.Fatalf("Eval: expected the receiver itself, got %v", got)
	}
}

// TestSecretEqualMethodDirectly exercises *vault.Secret's Equal method
// directly (all three branches: same value, different value, and a
// non-*Secret other) rather than through the cl equal/eq machinery, which
// never reaches it (see the block comment above). secret-equal is the only
// in-Lisp caller of this method.
func TestSecretEqualMethodDirectly(t *testing.T) {
	a := vault.NewSecret("hunter2")
	b := vault.NewSecret("hunter2")
	c := vault.NewSecret("other")
	if !a.Equal(b) {
		t.Fatal("expected two distinct secrets with the same value to be Equal")
	}
	if a.Equal(c) {
		t.Fatal("expected two secrets with different values to not be Equal")
	}
	if a.Equal(slip.String("hunter2")) {
		t.Fatal("expected a secret to not be Equal to a non-secret Object")
	}
}

// --- secret-equal --------------------------------------------------------
//
// secret-equal is the constant-time, value-comparing counterpart to equal
// for secrets: (secret-equal a b) is t for equal values regardless of
// object identity, unlike equal above.

func TestSecretEqualFnSameValue(t *testing.T) {
	(&sliptest.Function{
		Source: `(secret-equal (make-secret "hunter2") (make-secret "hunter2"))`,
		Expect: `t`,
	}).Test(t)
}

func TestSecretEqualFnDifferentValue(t *testing.T) {
	(&sliptest.Function{
		Source: `(secret-equal (make-secret "hunter2") (make-secret "other"))`,
		Expect: `nil`,
	}).Test(t)
}

func TestSecretEqualFnNonSecretArgumentIsTypeError(t *testing.T) {
	(&sliptest.Function{
		Source:    `(secret-equal (make-secret "hunter2") "hunter2")`,
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestSecretEqualFnWrongArgCount(t *testing.T) {
	// CheckArgCount (slip/argcounterror.go) raises a plain "error" condition,
	// not a type-error, for an arg count outside the allowed range.
	(&sliptest.Function{
		Source:    `(secret-equal (make-secret "hunter2"))`,
		PanicType: slip.ErrorSymbol,
	}).Test(t)
}
