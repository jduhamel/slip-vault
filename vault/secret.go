// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"crypto/subtle"
	"encoding/json"

	"github.com/ohler55/slip"
)

// SecretSymbol is the symbol with a value of "secret".
const SecretSymbol = slip.Symbol("secret")

const redacted = "#<secret>"

// Secret holds a sensitive string value. Every printed or simplified form of
// a Secret is the redacted #<secret> so the value does not leak through the
// REPL, format, describe, JSON conversion, or error messages. The only way to
// get the plaintext is the Value method or the secret-value function.
type Secret struct {
	val string
}

// NewSecret returns a Secret wrapping the value.
func NewSecret(value string) *Secret {
	return &Secret{val: value}
}

// Value returns the plaintext value of the secret.
func (obj *Secret) Value() string {
	return obj.val
}

// String representation of the Object.
func (obj *Secret) String() string {
	return redacted
}

// Append a buffer with a representation of the Object.
func (obj *Secret) Append(b []byte) []byte {
	return append(b, redacted...)
}

// GoString returns the redacted form so %#v does not reveal the value.
func (obj *Secret) GoString() string {
	return redacted
}

// Readably appends the redacted form even when printing readably so that
// ~s, prin1, and print show #<secret> instead of raising an error.
func (obj *Secret) Readably(b []byte, p *slip.Printer) []byte {
	return append(b, redacted...)
}

// Simplify the Object into the redacted string.
func (obj *Secret) Simplify() any {
	return redacted
}

// Equal returns true if the other Object is a Secret with the same value. The
// comparison is constant-time.
func (obj *Secret) Equal(other slip.Object) bool {
	if to, ok := other.(*Secret); ok && to != nil {
		return subtle.ConstantTimeCompare([]byte(obj.val), []byte(to.val)) == 1
	}
	return false
}

// Hierarchy returns the class hierarchy as symbols for the instance.
func (obj *Secret) Hierarchy() []slip.Symbol {
	return []slip.Symbol{SecretSymbol, slip.TrueSymbol}
}

// Eval returns self.
func (obj *Secret) Eval(s *slip.Scope, depth int) slip.Object {
	return obj
}

// secretObject wraps a value decoded from a Vault response as a Secret.
// Strings are wrapped as is. Other JSON values (numbers, booleans, arrays,
// and objects) are wrapped as their JSON encoding. A nil value stays nil.
func secretObject(s *slip.Scope, v any, depth int) slip.Object {
	switch tv := v.(type) {
	case nil:
		return nil
	case string:
		return NewSecret(tv)
	}
	b, err := json.Marshal(v)
	if err != nil {
		// The error text may include part of the value so it is not included.
		slip.ErrorPanic(s, depth, "a secret value could not be encoded as JSON")
	}
	return NewSecret(string(b))
}

// secretAlist converts a map of secret values into an alist of (key .
// #<secret>) with the keys sorted.
func secretAlist(s *slip.Scope, m map[string]any, depth int) slip.List {
	return sortedAlist(m, func(_ string, v any) slip.Object { return secretObject(s, v, depth) })
}
