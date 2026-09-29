// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ohler55/slip"
)

func mustBeDuration(s *slip.Scope, arg slip.Object, name string, depth int) (dur time.Duration) {
	if num, ok := arg.(slip.Real); ok {
		dur = time.Duration(num.RealValue() * float64(time.Second))
	} else {
		redactedTypePanic(s, depth, name, arg, "real")
	}
	return
}

func mustBeFixnum(s *slip.Scope, arg slip.Object, name string, depth int) int {
	num, ok := arg.(slip.Fixnum)
	if !ok {
		redactedTypePanic(s, depth, name, arg, "fixnum")
	}
	return int(num)
}

// timeoutContext returns a context that honors the :timeout keyword if it is
// present in keys, the keyword arguments of a method.
func timeoutContext(s *slip.Scope, keys slip.List, depth int) (context.Context, context.CancelFunc) {
	if v, has := slip.GetArgsKeyValue(keys, slip.Symbol(":timeout")); has {
		return context.WithTimeout(context.Background(), mustBeDuration(s, v, ":timeout", depth))
	}
	return context.WithCancel(context.Background())
}

// typeName returns the type of a value, as a type-error would describe it,
// without including the value itself which may be a secret.
func typeName(v slip.Object) string {
	if v == nil {
		return "nil"
	}
	return string(v.Hierarchy()[0])
}

// redactedTypePanic raises a type-error like slip.TypePanic but names only
// the type of value. The value may be a secret, or plaintext meant to be one,
// so it is left out of both the message and the :datum.
func redactedTypePanic(s *slip.Scope, depth int, use string, value slip.Object, wants ...string) {
	xt := make(slip.List, len(wants))
	for i, w := range wants {
		xt[i] = slip.Symbol(w)
	}
	obj := slip.FindClass("type-error").MakeInstance()
	obj.Init(s, slip.List{
		slip.Symbol(":expected-type"), xt,
		slip.Symbol(":message"),
		slip.String(fmt.Sprintf("%s must be a %s, not a %s.", use, strings.Join(wants, " or "), typeName(value))),
	}, depth)
	panic(obj)
}

// trimPath returns a string argument with leading and trailing slashes
// removed so mounts and paths such as "/secret/" can be used.
func trimPath(s *slip.Scope, arg slip.Object, name string, depth int) string {
	return strings.Trim(mustBeString(s, arg, name, depth), "/")
}

// mustBeString returns the string value of arg. Unlike slip.MustBeString the
// error only names the type of arg since a misplaced argument may hold a
// secret.
func mustBeString(s *slip.Scope, arg slip.Object, name string, depth int) string {
	str, ok := arg.(slip.String)
	if !ok {
		redactedTypePanic(s, depth, name, arg, "string")
	}
	return string(str)
}

// stringOrSecret returns the plaintext of a string or secret argument. The
// argument may hold a secret so an error only names its type.
func stringOrSecret(s *slip.Scope, arg slip.Object, name string, depth int) (str string) {
	switch ta := arg.(type) {
	case *Secret:
		str = ta.Value()
	case slip.String:
		str = string(ta)
	default:
		redactedTypePanic(s, depth, name, arg, "string", "secret")
	}
	return
}

// dataMap converts an alist or hash-table into the map sent to Vault. Secret
// values are unwrapped to their plaintext.
func dataMap(s *slip.Scope, arg slip.Object, name string, depth int) map[string]any {
	m := map[string]any{}
	switch ta := arg.(type) {
	case nil:
	case slip.HashTable:
		for k, v := range ta {
			m[mustBeString(s, k, name+" key", depth)] = toVaultValue(v)
		}
	case slip.List:
		for _, e := range ta {
			pair, ok := e.(slip.List)
			if !ok || len(pair) != 2 {
				slip.ErrorPanic(s, depth, "%s entries must be (key . value) pairs", name)
			}
			v := pair[1]
			if tail, ok := v.(slip.Tail); ok {
				v = tail.Value
			}
			m[mustBeString(s, pair[0], name+" key", depth)] = toVaultValue(v)
		}
	default:
		redactedTypePanic(s, depth, name, arg, "list", "hash-table")
	}
	return m
}

// toVaultValue converts a slip value into a value for a Vault request. Secrets
// are unwrapped at any depth rather than simplified to the redacted form.
// Nested alists, lists where every element is a (key . value) pair with a
// string or symbol key, and hash-tables become maps. Other lists and vectors
// become arrays.
func toVaultValue(v slip.Object) any {
	switch tv := v.(type) {
	case nil:
		return nil
	case *Secret:
		return tv.Value()
	case slip.String:
		return string(tv)
	case slip.Tail:
		return toVaultValue(tv.Value)
	case slip.List:
		if isAlist(tv) {
			m := make(map[string]any, len(tv))
			for _, e := range tv {
				pair := e.(slip.List)
				m[vaultKey(pair[0])] = toVaultValue(pair[1].(slip.Tail).Value)
			}
			return m
		}
		list := make([]any, len(tv))
		for i, e := range tv {
			list[i] = toVaultValue(e)
		}
		return list
	case slip.HashTable:
		m := make(map[string]any, len(tv))
		for k, e := range tv {
			m[vaultKey(k)] = toVaultValue(e)
		}
		return m
	case slip.ArrayLike:
		return toVaultValue(tv.AsList())
	}
	// Only non-container values that can not hold a secret remain.
	return v.Simplify()
}

// isAlist returns true if list is not empty and every element is a dotted
// (key . value) pair with a string or symbol key.
func isAlist(list slip.List) bool {
	for _, e := range list {
		pair, ok := e.(slip.List)
		if !ok || len(pair) != 2 {
			return false
		}
		if _, ok = pair[1].(slip.Tail); !ok {
			return false
		}
		switch pair[0].(type) {
		case slip.String, slip.Symbol:
		default:
			return false
		}
	}
	return 0 < len(list)
}

// vaultKey converts a map key to a string.
func vaultKey(k slip.Object) string {
	switch tk := k.(type) {
	case slip.String:
		return string(tk)
	case slip.Symbol:
		return string(tk)
	}
	return slip.ObjectString(k)
}

// toObject converts a value decoded from a Vault response into a plain,
// non-secret slip value. Maps become alists sorted by key.
func toObject(v any) slip.Object {
	switch tv := v.(type) {
	case json.Number:
		if i, err := tv.Int64(); err == nil {
			return slip.Fixnum(i)
		}
		if f, err := tv.Float64(); err == nil {
			return slip.DoubleFloat(f)
		}
		return slip.String(tv)
	case map[string]any:
		return sortedAlist(tv, func(_ string, v any) slip.Object { return toObject(v) })
	case []any:
		list := make(slip.List, len(tv))
		for i, e := range tv {
			list[i] = toObject(e)
		}
		return list
	}
	return slip.SimpleObject(v)
}

// sortedAlist converts a map into an alist of (key . value) sorted by key
// using conv to convert each value.
func sortedAlist(m map[string]any, conv func(k string, v any) slip.Object) slip.List {
	if m == nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	alist := make(slip.List, 0, len(keys))
	for _, k := range keys {
		if v := conv(k, m[k]); v != nil {
			alist = append(alist, slip.List{slip.String(k), slip.Tail{Value: v}})
		} else {
			alist = append(alist, slip.List{slip.String(k)})
		}
	}
	return alist
}

// keyPair returns a (key . value) pair with a keyword key. A nil value gives
// a list of just the key which is the same as (key . nil).
func keyPair(key string, value slip.Object) slip.List {
	if value == nil {
		return slip.List{slip.Symbol(key)}
	}
	return slip.List{slip.Symbol(key), slip.Tail{Value: value}}
}

// boolObject converts a bool to t or nil.
func boolObject(b bool) slip.Object {
	if b {
		return slip.True
	}
	return nil
}
