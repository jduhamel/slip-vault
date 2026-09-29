// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type kvDeleteCaller struct{}

func (caller kvDeleteCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":kv-delete", len(args), 2, 6)
	ac := selfAPI(s, depth)
	mount := trimPath(s, args[0], "mount", depth)
	path := trimPath(s, args[1], "path", depth)
	keys := args[2:]
	ctx, cf := timeoutContext(s, keys, depth)
	defer cf()

	var err error
	if v, has := slip.GetArgsKeyValue(keys, slip.Symbol(":versions")); has {
		list, ok := v.(slip.List)
		if !ok {
			redactedTypePanic(s, depth, ":versions", v, "list")
		}
		versions := make([]int, len(list))
		for i, e := range list {
			versions[i] = mustBeFixnum(s, e, ":versions element", depth)
		}
		err = ac.KVv2(mount).DeleteVersions(ctx, path, versions)
	} else {
		err = ac.KVv2(mount).Delete(ctx, path)
	}
	if err != nil {
		panic(err)
	}
	return nil
}

func (caller kvDeleteCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":kv-delete",
		Text: `Soft deletes the latest version, or the _:versions_ given, of the secret at
_path_ in the KV version 2 engine mounted at _mount_. Deleted versions can be
undeleted with the Vault CLI or API. Returns _nil_.`,
		Args: []*slip.DocArg{
			{Name: "mount", Type: "string", Text: "The mount path of the KV version 2 engine."},
			{Name: "path", Type: "string", Text: "The path of the secret in the engine."},
			{Name: "&key"},
			{Name: ":versions", Type: "list", Text: "A list of version numbers to delete."},
			{Name: ":timeout", Type: "real", Text: "The number of seconds to wait before timing out."},
		},
	}
}
