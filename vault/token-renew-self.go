// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type tokenRenewSelfCaller struct{}

func (caller tokenRenewSelfCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":token-renew-self", len(args), 0, 4)
	ac := selfAPI(s, depth)
	var increment int
	if v, has := slip.GetArgsKeyValue(args, slip.Symbol(":increment")); has {
		increment = int(mustBeDuration(s, v, ":increment", depth).Seconds())
	}
	ctx, cf := timeoutContext(s, args, depth)
	defer cf()

	secret, err := ac.Auth().Token().RenewSelfWithContext(ctx, increment)
	if err != nil {
		panic(err)
	}
	if secret == nil || secret.Auth == nil {
		return nil
	}
	return slip.Fixnum(secret.Auth.LeaseDuration)
}

func (caller tokenRenewSelfCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":token-renew-self",
		Text: `Renews the client token and returns the new ttl in seconds. Root tokens
and other non-renewable tokens raise an error.`,
		Return: "fixnum",
		Args: []*slip.DocArg{
			{Name: "&key"},
			{
				Name: ":increment",
				Type: "real",
				Text: "The requested ttl extension in seconds. Defaults to the token's own ttl.",
			},
			{Name: ":timeout", Type: "real", Text: "The number of seconds to wait before timing out."},
		},
	}
}
