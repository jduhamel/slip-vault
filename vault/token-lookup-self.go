// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type tokenLookupSelfCaller struct{}

func (caller tokenLookupSelfCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":token-lookup-self", len(args), 0, 2)
	ac := selfAPI(s, depth)
	ctx, cf := timeoutContext(s, args, depth)
	defer cf()

	secret, err := ac.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		panic(err)
	}
	if secret == nil {
		return nil
	}
	return sortedAlist(secret.Data, func(k string, v any) slip.Object {
		if tokenFields[k] {
			return secretObject(s, v, depth)
		}
		return toObject(v)
	})
}

// tokenFields are the token lookup fields that can be used to act on the
// token, the id being the token itself.
var tokenFields = map[string]bool{
	"id":           true,
	"accessor":     true,
	"cubbyhole_id": true,
}

func (caller tokenLookupSelfCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":token-lookup-self",
		Text: `Returns information about the client token, such as the policies and ttl,
as an alist sorted by key. The "id" entry is the token and it, the "accessor",
and the "cubbyhole_id" are each a #<secret>.`,
		Return: "list",
		Args: []*slip.DocArg{
			{Name: "&key"},
			{Name: ":timeout", Type: "real", Text: "The number of seconds to wait before timing out."},
		},
	}
}
