// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type renewalStatusCaller struct{}

func (caller renewalStatusCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":renewal-status", len(args), 0, 0)
	c := selfClient(s, depth)
	last, err := c.renewStatus()
	var (
		lastObj slip.Object
		errObj  slip.Object
	)
	if !last.IsZero() {
		lastObj = slip.Time(last)
	}
	if err != nil {
		errObj = slip.String(err.Error())
	}
	return slip.List{
		slip.Symbol(":auto-renew"), boolObject(c.autoRenew),
		slip.Symbol(":renewable"), boolObject(c.renewable),
		slip.Symbol(":last-renewal"), lastObj,
		slip.Symbol(":error"), errObj,
	}
}

func (caller renewalStatusCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":renewal-status",
		Text: `Returns the state of the background token renewal as a plist:
  :auto-renew    _t_ if auto-renew was requested on connect
  :renewable     _t_ if the token is renewable, root tokens are not
  :last-renewal  the time of the last renewal or AppRole login, or _nil_
  :error         the error that stopped renewal as a string, or _nil_
No secrets are included.`,
		Return: "list",
	}
}
