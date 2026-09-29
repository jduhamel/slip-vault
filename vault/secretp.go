// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
)

func defSecretp() {
	slip.Define(
		func(args slip.List) slip.Object {
			f := Secretp{Function: slip.Function{Name: "secretp", Args: args}}
			f.Self = &f
			return &f
		},
		&slip.FuncDoc{
			Name: "secretp",
			Args: []*slip.DocArg{
				{
					Name: "object",
					Type: "object",
					Text: "The object to check.",
				},
			},
			Return: "t|nil",
			Text:   `__secretp__ returns _true_ if _object_ is a _secret_.`,
			Examples: []string{
				`(secretp (make-secret "x")) => t`,
				`(secretp "x") => nil`,
			},
		}, &Pkg)
}

// Secretp represents the secretp function.
type Secretp struct {
	slip.Function
}

// Call the function with the arguments provided.
func (f *Secretp) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	slip.CheckArgCount(s, depth, f, args, 1, 1)
	if _, ok := args[0].(*Secret); ok {
		return slip.True
	}
	return nil
}
