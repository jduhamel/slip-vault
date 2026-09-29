// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"github.com/hashicorp/vault/api"
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

type readCaller struct{}

func (caller readCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	slip.MethodArgCountCheck(s, depth, self, ":read", len(args), 1, 3)
	ac := selfAPI(s, depth)
	path := trimPath(s, args[0], "path", depth)
	ctx, cf := timeoutContext(s, args[1:], depth)
	defer cf()

	secret, err := ac.Logical().ReadWithContext(ctx, path)
	if err != nil {
		panic(err)
	}
	if secret == nil {
		return nil
	}
	return responseAlist(s, secret, depth)
}

func (caller readCaller) FuncDocs() *slip.FuncDoc {
	return &slip.FuncDoc{
		Name: ":read",
		Text: `Reads the raw Vault _path_, for example "database/creds/app", and returns
the response as an alist with these entries:
  :data            an alist of (key . #<secret>) sorted by key
  :lease-id        the lease id, a string
  :lease-duration  the lease duration in seconds
  :renewable       _t_ if the lease can be renewed
  :auth            only if the response has auth information, an alist of
                   :client-token and :accessor, both #<secret>, and
                   :policies and :lease-duration
String data values are wrapped as is, other JSON values, including nested
objects, are wrapped as their JSON encoding. If there is nothing at _path_ then
_nil_ is returned. For KV version 2 secrets use _:kv-get_ instead.`,
		Return: "list",
		Args: []*slip.DocArg{
			{Name: "path", Type: "string", Text: "The full Vault path including the mount."},
			{Name: "&key"},
			{Name: ":timeout", Type: "real", Text: "The number of seconds to wait before timing out."},
		},
	}
}

// responseAlist converts a raw Vault response into the alist returned by
// :read and :write. Data values and the auth token and accessor are secrets.
func responseAlist(s *slip.Scope, secret *api.Secret, depth int) slip.List {
	alist := slip.List{
		keyPair(":data", secretAlist(s, secret.Data, depth)),
		keyPair(":lease-id", slip.String(secret.LeaseID)),
		keyPair(":lease-duration", slip.Fixnum(secret.LeaseDuration)),
		keyPair(":renewable", boolObject(secret.Renewable)),
	}
	if auth := secret.Auth; auth != nil {
		policies := make(slip.List, len(auth.Policies))
		for i, p := range auth.Policies {
			policies[i] = slip.String(p)
		}
		alist = append(alist, keyPair(":auth", slip.List{
			keyPair(":client-token", NewSecret(auth.ClientToken)),
			keyPair(":accessor", NewSecret(auth.Accessor)),
			keyPair(":policies", policies),
			keyPair(":lease-duration", slip.Fixnum(auth.LeaseDuration)),
		}))
	}
	return alist
}
