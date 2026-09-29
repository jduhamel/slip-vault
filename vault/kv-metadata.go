// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type kvMetadataCaller struct{}

func (caller kvMetadataCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":kv-metadata", len(args), 2, 4)
	ac := selfAPI(s, depth)
	mount := trimPath(s, args[0], "mount", depth)
	path := trimPath(s, args[1], "path", depth)
	ctx, cf := timeoutContext(s, args[2:], depth)
	defer cf()

	// KVv2.GetMetadata does not keep the raw response and decodes the times
	// so a logical read is used to return the metadata as Vault sent it.
	secret, err := ac.Logical().ReadWithContext(ctx, mount+"/metadata/"+path)
	if err != nil {
		panic(err)
	}
	if secret == nil {
		return nil
	}
	return toObject(secret.Data)
}

func (caller kvMetadataCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":kv-metadata",
		Text: `Returns the metadata of the secret at _path_ in the KV version 2 engine
mounted at _mount_ as an alist sorted by key. The metadata includes the current
version, the created and updated times, and the metadata of each version. No
secret values are included. If there is no secret at _path_ then _nil_ is
returned.`,
		Return: "list",
		Args: []*slip.DocArg{
			{Name: "mount", Type: "string", Text: "The mount path of the KV version 2 engine."},
			{Name: "path", Type: "string", Text: "The path of the secret in the engine."},
			{Name: "&key"},
			{Name: ":timeout", Type: "real", Text: "The number of seconds to wait before timing out."},
		},
	}
}
