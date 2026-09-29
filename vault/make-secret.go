// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
)

func defMakeSecret() {
	slip.Define(
		func(args slip.List) slip.Object {
			f := MakeSecret{Function: slip.Function{Name: "make-secret", Args: args}}
			f.Self = &f
			return &f
		},
		&slip.FuncDoc{
			Name: "make-secret",
			Args: []*slip.DocArg{
				{
					Name: "value",
					Type: "string",
					Text: "The string to wrap as a secret.",
				},
			},
			Return: "secret",
			Text: `__make-secret__ wraps _value_ in a _secret_ that always prints as #<secret>.
If _value_ is already a _secret_ it is returned as is.`,
			Examples: []string{
				`(make-secret "example-value") => #<secret>`,
			},
		}, &Pkg)
}

// MakeSecret represents the make-secret function.
type MakeSecret struct {
	slip.Function
}

// Call the function with the arguments provided.
func (f *MakeSecret) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	slip.CheckArgCount(s, depth, f, args, 1, 1)
	switch ta := args[0].(type) {
	case *Secret:
		return ta
	case slip.String:
		return NewSecret(string(ta))
	default:
		redactedTypePanic(s, depth, "value", ta, "string")
	}
	return nil
}
