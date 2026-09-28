// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type kvPatchCaller struct{}

func (caller kvPatchCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":kv-patch", len(args), 3, 5)
	ac := selfAPI(s, depth)
	mount := trimPath(s, args[0], "mount", depth)
	path := trimPath(s, args[1], "path", depth)
	data := dataMap(s, args[2], "data", depth)
	ctx, cf := timeoutContext(s, args[3:], depth)
	defer cf()

	kvs, err := ac.KVv2(mount).Patch(ctx, path, data)
	if err != nil {
		panic(err)
	}
	return versionMetadata(kvs)
}

func (caller kvPatchCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":kv-patch",
		Text: `Merges _data_ into the latest version of the existing secret at _path_ in
the KV version 2 engine mounted at _mount_, creating a new version. Keys not
in _data_ are kept. An error is raised if the secret does not exist. Returns
the version metadata as an alist.`,
		Return: "list",
		Args: []*slip.DocArg{
			{Name: "mount", Type: "string", Text: "The mount path of the KV version 2 engine."},
			{Name: "path", Type: "string", Text: "The path of the secret in the engine."},
			{Name: "data", Type: "list|hash-table", Text: "The keys and values to merge."},
			{Name: "&key"},
			{Name: ":timeout", Type: "real", Text: "The number of seconds to wait before timing out."},
		},
	}
}
