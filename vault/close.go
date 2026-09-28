// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type closeCaller struct{}

func (caller closeCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":close", len(args), 0, 0)
	if c, ok := self.Any.(*Client); ok {
		c.close()
	}
	return nil
}

func (caller closeCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":close",
		Text: `Stops any background token renewal, revokes the token if it came from an
AppRole login, and clears the token. Any further method calls on the client
raise an error. Closing an already closed client does nothing.`,
	}
}
