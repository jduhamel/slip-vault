// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type kvListCaller struct{}

func (caller kvListCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":kv-list", len(args), 2, 4)
	ac := selfAPI(s, depth)
	mount := trimPath(s, args[0], "mount", depth)
	path := trimPath(s, args[1], "path", depth)
	ctx, cf := timeoutContext(s, args[2:], depth)
	defer cf()

	secret, err := ac.Logical().ListWithContext(ctx, mount+"/metadata/"+path)
	if err != nil {
		panic(err)
	}
	if secret == nil {
		return nil
	}
	raw, _ := secret.Data["keys"].([]any)
	keys := make(slip.List, 0, len(raw))
	for _, k := range raw {
		if str, ok := k.(string); ok {
			keys = append(keys, slip.String(str))
		}
	}
	return keys
}

func (caller kvListCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":kv-list",
		Text: `Lists the keys under _path_ in the KV version 2 engine mounted at _mount_.
Keys that end with a / are folders. Key names are not secret so a list of
plain strings is returned, or _nil_ if there is nothing under _path_.`,
		Return: "list",
		Args: []*slip.DocArg{
			{Name: "mount", Type: "string", Text: "The mount path of the KV version 2 engine."},
			{Name: "path", Type: "string", Text: `The folder to list. Use "" for the top level.`},
			{Name: "&key"},
			{Name: ":timeout", Type: "real", Text: "The number of seconds to wait before timing out."},
		},
	}
}
