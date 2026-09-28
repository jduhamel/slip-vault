// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type kvGetFieldCaller struct{}

func (caller kvGetFieldCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":kv-get-field", len(args), 3, 7)
	field := mustBeString(s, args[2], "field", depth)
	kvs := kvRead(s, args, 3, depth)
	if kvs == nil {
		return nil
	}
	return secretObject(s, kvs.Data[field], depth)
}

func (caller kvGetFieldCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":kv-get-field",
		Text: `Reads the secret at _path_ in the KV version 2 engine mounted at _mount_ and
returns the value of _field_ as a #<secret>. If there is no secret at _path_ or
the secret has no _field_ then _nil_ is returned.`,
		Return: "secret",
		Args: []*slip.DocArg{
			{Name: "mount", Type: "string", Text: "The mount path of the KV version 2 engine."},
			{Name: "path", Type: "string", Text: "The path of the secret in the engine."},
			{Name: "field", Type: "string", Text: "The key of the value to return."},
			{Name: "&key"},
			{Name: ":version", Type: "fixnum", Text: "The version to read. Defaults to the latest."},
			{Name: ":timeout", Type: "real", Text: "The number of seconds to wait before timing out."},
		},
	}
}
