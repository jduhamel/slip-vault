// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
)

func defSecretEqual() {
	slip.Define(
		func(args slip.List) slip.Object {
			f := SecretEqual{Function: slip.Function{Name: "secret-equal", Args: args}}
			f.Self = &f
			return &f
		},
		&slip.FuncDoc{
			Name: "secret-equal",
			Args: []*slip.DocArg{
				{
					Name: "secret-1",
					Type: "secret",
					Text: "The first secret to compare.",
				},
				{
					Name: "secret-2",
					Type: "secret",
					Text: "The second secret to compare.",
				},
			},
			Return: "t|nil",
			Text: `__secret-equal__ returns _true_ if _secret-1_ and _secret-2_ hold the same
value. The comparison takes the same time whatever the values so it does not
reveal how much of a value matched. Both arguments must be secrets.`,
			Examples: []string{
				`(secret-equal (make-secret "x") (make-secret "x")) => t`,
				`(secret-equal (make-secret "x") (make-secret "y")) => nil`,
			},
		}, &Pkg)
}

// SecretEqual represents the secret-equal function.
type SecretEqual struct {
	slip.Function
}

// Call the function with the arguments provided.
func (f *SecretEqual) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	slip.CheckArgCount(s, depth, f, args, 2, 2)
	x, ok := args[0].(*Secret)
	if !ok {
		redactedTypePanic(s, depth, "secret-1", args[0], "secret")
	}
	y, ok := args[1].(*Secret)
	if !ok {
		redactedTypePanic(s, depth, "secret-2", args[1], "secret")
	}
	if x.Equal(y) {
		return slip.True
	}
	return nil
}
