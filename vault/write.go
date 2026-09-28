// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type writeCaller struct{}

func (caller writeCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":write", len(args), 2, 4)
	ac := selfAPI(s, depth)
	path := trimPath(s, args[0], "path", depth)
	data := dataMap(s, args[1], "data", depth)
	ctx, cf := timeoutContext(s, args[2:], depth)
	defer cf()

	secret, err := ac.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		panic(err)
	}
	if secret == nil {
		return nil
	}
	return responseAlist(s, secret, depth)
}

func (caller writeCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":write",
		Text: `Writes _data_ to the raw Vault _path_. The _data_ is an alist of
(key . value) or a hash-table. Values may be strings, secrets, or other simple
values, including secrets nested in lists, alists, and hash-tables. If Vault
returns a response it is returned as an alist in the same form as _:read_ with
:data, :lease-id, :lease-duration, :renewable, and :auth entries, otherwise
_nil_ is returned. For KV version 2 secrets use _:kv-put_ instead.`,
		Return: "list",
		Args: []*slip.DocArg{
			{Name: "path", Type: "string", Text: "The full Vault path including the mount."},
			{Name: "data", Type: "list|hash-table", Text: "The keys and values to write."},
			{Name: "&key"},
			{Name: ":timeout", Type: "real", Text: "The number of seconds to wait before timing out."},
		},
	}
}
