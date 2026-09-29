// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type kvPutCaller struct{}

func (caller kvPutCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":kv-put", len(args), 3, 7)
	ac := selfAPI(s, depth)
	mount := trimPath(s, args[0], "mount", depth)
	path := trimPath(s, args[1], "path", depth)
	data := dataMap(s, args[2], "data", depth)
	keys := args[3:]
	var opts []api.KVOption
	if v, has := slip.GetArgsKeyValue(keys, slip.Symbol(":cas")); has {
		opts = append(opts, api.WithCheckAndSet(mustBeFixnum(s, v, ":cas", depth)))
	}
	ctx, cf := timeoutContext(s, keys, depth)
	defer cf()

	kvs, err := ac.KVv2(mount).Put(ctx, path, data, opts...)
	if err != nil {
		panic(err)
	}
	return versionMetadata(kvs)
}

func (caller kvPutCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":kv-put",
		Text: `Writes _data_ as a new version of the secret at _path_ in the KV version 2
engine mounted at _mount_, replacing all keys. The _data_ is an alist of
(key . value) or a hash-table. Values may be strings, secrets, or other simple
values. Returns the version metadata as an alist.`,
		Return: "list",
		Args: []*slip.DocArg{
			{Name: "mount", Type: "string", Text: "The mount path of the KV version 2 engine."},
			{Name: "path", Type: "string", Text: "The path of the secret in the engine."},
			{Name: "data", Type: "list|hash-table", Text: "The keys and values to write."},
			{Name: "&key"},
			{
				Name: ":cas",
				Type: "fixnum",
				Text: `Check-and-set version. The write only succeeds if the current version
matches. A value of 0 only allows the write if the secret does not exist.`,
			},
			{Name: ":timeout", Type: "real", Text: "The number of seconds to wait before timing out."},
		},
	}
}

// versionMetadata returns the version metadata of a KV v2 write as an alist.
// The API client replaces an empty deletion_time with a zero time.Time in the
// raw data so it is put back to the string form Vault returned.
func versionMetadata(kvs *api.KVSecret) slip.Object {
	if kvs == nil || kvs.Raw == nil {
		return nil
	}
	data := make(map[string]any, len(kvs.Raw.Data))
	for k, v := range kvs.Raw.Data {
		if tm, ok := v.(time.Time); ok {
			if tm.IsZero() {
				v = ""
			} else {
				v = tm.Format(time.RFC3339Nano)
			}
		}
		data[k] = v
	}
	return toObject(data)
}
