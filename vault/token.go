// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type tokenCaller struct{}

func (caller tokenCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":token", len(args), 0, 0)
	if token := selfAPI(s, depth).Token(); 0 < len(token) {
		return NewSecret(token)
	}
	return nil
}

func (caller tokenCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name:   ":token",
		Text:   `Returns the token the client is using as a #<secret>.`,
		Return: "secret",
	}
}
