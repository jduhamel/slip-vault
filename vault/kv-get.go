// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"errors"

	"github.com/hashicorp/vault/api"
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type kvGetCaller struct{}

func (caller kvGetCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":kv-get", len(args), 2, 6)
	kvs := kvRead(s, args, 2, depth)
	if kvs == nil {
		return nil
	}
	return secretAlist(s, kvs.Data, depth)
}

func (caller kvGetCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":kv-get",
		Text: `Reads the secret at _path_ in the KV version 2 engine mounted at _mount_ and
returns an alist of (key . #<secret>) sorted by key. String values are wrapped
as is, other JSON values are wrapped as their JSON encoding. If there is no
secret at _path_ then _nil_ is returned.`,
		Return: "list",
		Args: []*slip.DocArg{
			{Name: "mount", Type: "string", Text: "The mount path of the KV version 2 engine."},
			{Name: "path", Type: "string", Text: "The path of the secret in the engine."},
			{Name: "&key"},
			{Name: ":version", Type: "fixnum", Text: "The version to read. Defaults to the latest."},
			{Name: ":timeout", Type: "real", Text: "The number of seconds to wait before timing out."},
		},
	}
}

// kvRead reads a KV v2 secret using the mount and path arguments and the
// :version and :timeout keywords that start at args[keyStart]. A missing
// secret returns nil.
func kvRead(s *slip.Scope, args slip.List, keyStart, depth int) *api.KVSecret {
	ac := selfAPI(s, depth)
	mount := trimPath(s, args[0], "mount", depth)
	path := trimPath(s, args[1], "path", depth)
	keys := args[keyStart:]
	ctx, cf := timeoutContext(s, keys, depth)
	defer cf()

	var (
		kvs *api.KVSecret
		err error
	)
	if v, has := slip.GetArgsKeyValue(keys, slip.Symbol(":version")); has {
		kvs, err = ac.KVv2(mount).GetVersion(ctx, path, mustBeFixnum(s, v, ":version", depth))
	} else {
		kvs, err = ac.KVv2(mount).Get(ctx, path)
	}
	if err != nil {
		if errors.Is(err, api.ErrSecretNotFound) {
			return nil
		}
		panic(err)
	}
	return kvs
}
