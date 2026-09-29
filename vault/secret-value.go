// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
)

func defSecretValue() {
	slip.Define(
		func(args slip.List) slip.Object {
			f := SecretValue{Function: slip.Function{Name: "secret-value", Args: args}}
			f.Self = &f
			return &f
		},
		&slip.FuncDoc{
			Name: "secret-value",
			Args: []*slip.DocArg{
				{
					Name: "secret",
					Type: "secret",
					Text: "The secret to reveal.",
				},
			},
			Return: "string",
			Text: `__secret-value__ returns the plaintext string held by _secret_. This is the
only way to get the value out of a _secret_.`,
			Examples: []string{
				`(secret-value (make-secret "example-value")) => "example-value"`,
			},
		}, &Pkg)
}

// SecretValue represents the secret-value function.
type SecretValue struct {
	slip.Function
}

// Call the function with the arguments provided.
func (f *SecretValue) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	slip.CheckArgCount(s, depth, f, args, 1, 1)
	sec, ok := args[0].(*Secret)
	if !ok {
		redactedTypePanic(s, depth, "secret", args[0], "secret")
	}
	return slip.String(sec.Value())
}
