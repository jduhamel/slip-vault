// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ohler55/slip"
	"github.com/ohler55/slip/pkg/flavors"
)

// connectSpec collects the vault-connect options before the client is built.
type connectSpec struct {
	address   string
	token     string
	hasToken  bool
	namespace string
	timeout   time.Duration
	tls       api.TLSConfig
	hasTLS    bool
	approle   []string // role-id, secret-id, mount
	autoRenew bool
	increment int
}

type conOpt struct {
	doc    *slip.DocArg
	update func(spec *connectSpec, s *slip.Scope, v slip.Object)
}

var conOptMap = map[string]*conOpt{
	":address": {
		doc: &slip.DocArg{
			Name: ":address",
			Type: "string",
			Text: `The URL of the Vault server. Defaults to the VAULT_ADDR environment variable
or https://127.0.0.1:8200.`,
		},
		update: func(spec *connectSpec, s *slip.Scope, v slip.Object) {
			spec.address = slip.MustBeString(v, ":address")
		},
	},
	":token": {
		doc: &slip.DocArg{
			Name: ":token",
			Type: "string|secret",
			Text: `The token used to authenticate. Defaults to the VAULT_TOKEN environment variable.`,
		},
		update: func(spec *connectSpec, s *slip.Scope, v slip.Object) {
			spec.token = stringOrSecret(s, v, ":token", 0)
			spec.hasToken = true
		},
	},
	":namespace": {
		doc: &slip.DocArg{
			Name: ":namespace",
			Type: "string",
			Text: `The Vault Enterprise namespace. Defaults to the VAULT_NAMESPACE environment variable.`,
		},
		update: func(spec *connectSpec, s *slip.Scope, v slip.Object) {
			spec.namespace = slip.MustBeString(v, ":namespace")
		},
	},
	":timeout": {
		doc: &slip.DocArg{
			Name: ":timeout",
			Type: "real",
			Text: `The number of seconds to wait for each request before timing out.`,
		},
		update: func(spec *connectSpec, s *slip.Scope, v slip.Object) {
			spec.timeout = mustBeDuration(s, v, ":timeout", 0)
		},
	},
	":ca-cert": {
		doc: &slip.DocArg{
			Name: ":ca-cert",
			Type: "string",
			Text: `The path to a PEM-encoded CA certificate file used to verify the server.`,
		},
		update: func(spec *connectSpec, s *slip.Scope, v slip.Object) {
			spec.tls.CACert = slip.MustBeString(v, ":ca-cert")
			spec.hasTLS = true
		},
	},
	":client-cert": {
		doc: &slip.DocArg{
			Name: ":client-cert",
			Type: "string",
			Text: `The path to a PEM-encoded client certificate file.`,
		},
		update: func(spec *connectSpec, s *slip.Scope, v slip.Object) {
			spec.tls.ClientCert = slip.MustBeString(v, ":client-cert")
			spec.hasTLS = true
		},
	},
	":client-key": {
		doc: &slip.DocArg{
			Name: ":client-key",
			Type: "string",
			Text: `The path to a PEM-encoded private key file for the client certificate.`,
		},
		update: func(spec *connectSpec, s *slip.Scope, v slip.Object) {
			spec.tls.ClientKey = slip.MustBeString(v, ":client-key")
			spec.hasTLS = true
		},
	},
	":tls-skip-verify": {
		doc: &slip.DocArg{
			Name: ":tls-skip-verify",
			Type: "boolean",
			Text: `If non-nil the server certificate is not verified. Use for testing only.`,
		},
		update: func(spec *connectSpec, s *slip.Scope, v slip.Object) {
			spec.tls.Insecure = v != nil
			spec.hasTLS = true
		},
	},
	":auto-renew": {
		doc: &slip.DocArg{
			Name: ":auto-renew",
			Type: "boolean",
			Text: `If non-nil, the default, a renewable token is renewed in the background
before it expires. When an AppRole token reaches its max ttl a new login is
made. Other tokens that can no longer be renewed cause later method calls to
raise a "vault token expired" error.`,
		},
		update: func(spec *connectSpec, s *slip.Scope, v slip.Object) {
			spec.autoRenew = v != nil
		},
	},
	":renew-increment": {
		doc: &slip.DocArg{
			Name: ":renew-increment",
			Type: "real",
			Text: `The ttl extension in seconds requested on each automatic renewal. Defaults
to the token's own ttl.`,
		},
		update: func(spec *connectSpec, s *slip.Scope, v slip.Object) {
			spec.increment = int(mustBeDuration(s, v, ":renew-increment", 0).Seconds())
		},
	},
	":approle": {
		doc: &slip.DocArg{
			Name: ":approle",
			Type: "list",
			Text: `A list of (_role-id_ _secret-id_ [_mount_]) used to log in with the AppRole
auth method. The _mount_ defaults to "approle". The token returned by the
login replaces any _:token_. The role-id and secret-id may be strings or
secrets. With _:auto-renew_ they are kept in memory to log in again when the
token reaches its max ttl.`,
		},
		update: func(spec *connectSpec, s *slip.Scope, v slip.Object) {
			list, ok := v.(slip.List)
			if !ok || len(list) < 2 || 3 < len(list) {
				// The value is not included in the error as it may hold the secret-id.
				slip.ErrorPanic(s, 0, ":approle must be a list of (role-id secret-id [mount])")
			}
			spec.approle = []string{
				stringOrSecret(s, list[0], ":approle role-id", 0),
				stringOrSecret(s, list[1], ":approle secret-id", 0),
				"approle",
			}
			if len(list) == 3 {
				spec.approle[2] = slip.MustBeString(list[2], ":approle mount")
			}
		},
	},
}

func initConnect() {
	args := make([]*slip.DocArg, len(conOptMap)+1)
	keys := make([]string, 0, len(conOptMap))
	for k := range conOptMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	args[0] = &slip.DocArg{Name: "&key"}
	for i, k := range keys {
		args[i+1] = conOptMap[k].doc
	}
	slip.Define(
		func(args slip.List) slip.Object {
			f := Connect{Function: slip.Function{Name: "vault-connect", Args: args}}
			f.Self = &f
			return &f
		},
		&slip.FuncDoc{
			Name:   "vault-connect",
			Args:   args,
			Return: "vault-client",
			Text: `__vault-connect__ creates a client for a HashiCorp Vault or OpenBao server.
Options not given are taken from the standard VAULT_* environment variables.
If _:approle_ is given a login is performed. The token is then verified with
a token self lookup so a bad address or token raises an error immediately.
Renewable tokens are renewed in the background unless _:auto-renew_ is nil.`,
			Examples: []string{
				`(vault-connect :address "http://127.0.0.1:8200" :token "root") => #<vault-client 12345>`,
			},
		}, &Pkg)
}

// Connect represents the vault-connect function.
type Connect struct {
	slip.Function
}

// Call the function with the arguments provided.
func (f *Connect) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := clientFlavor.MakeInstance().(*flavors.Instance)
	self.Init(s, args, depth)

	return self
}

type clientInitCaller struct{}

func (caller clientInitCaller) Call(s *slip.Scope, args slip.List, depth int) slip.Object {
	self := s.Get("self").(*flavors.Instance)
	if 0 < len(args) {
		args = args[0].(slip.List)
	}
	spec := connectSpec{autoRenew: true}
	for i := 0; i < len(args)-1; i += 2 {
		key := strings.ToLower(string(args[i].(slip.Symbol)))
		conOptMap[key].update(&spec, s, args[i+1])
	}
	self.Any = spec.connect(s, depth)

	return nil
}

func (caller clientInitCaller) FuncDocs() *slip.FuncDoc {
	fd := slip.FuncDoc{
		Name: ":init",
		Args: []*slip.DocArg{
			{Name: "&key"},
		},
		Text: "Sets the initial value when _make-instance_ is called.",
		Kind: slip.MethodSymbol,
	}
	keys := make([]string, 0, len(conOptMap))
	for k := range conOptMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fd.Args = append(fd.Args, conOptMap[k].doc)
	}
	return &fd
}

// connect builds the API client, logs in with AppRole if requested, verifies
// the token, and starts renewing it if it is renewable and auto-renew is on.
func (spec *connectSpec) connect(s *slip.Scope, depth int) *Client {
	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		panic(cfg.Error)
	}
	if 0 < len(spec.address) {
		cfg.Address = spec.address
		// VAULT_AGENT_ADDR would otherwise take precedence over :address.
		cfg.AgentAddress = ""
	}
	if 0 < spec.timeout {
		cfg.Timeout = spec.timeout
	}
	if spec.hasTLS {
		if err := cfg.ConfigureTLS(&spec.tls); err != nil {
			panic(err)
		}
	}
	ac, err := api.NewClient(cfg)
	if err != nil {
		panic(err)
	}
	if 0 < len(spec.namespace) {
		ac.SetNamespace(spec.namespace)
	}
	if spec.hasToken {
		ac.SetToken(spec.token)
	}
	ctx := context.Background()
	if 0 < spec.timeout {
		var cf context.CancelFunc
		ctx, cf = context.WithTimeout(ctx, spec.timeout)
		defer cf()
	}
	c := &Client{
		api:       ac,
		autoRenew: spec.autoRenew,
		increment: spec.increment,
		revoke:    spec.approle != nil,
		approle:   spec.approle,
	}
	var auth *api.SecretAuth
	if spec.approle != nil {
		// VAULT_TOKEN or :token is not sent with the login.
		ac.ClearToken()
		if auth, err = c.login(ctx); err != nil {
			panic(err)
		}
		ac.SetToken(auth.ClientToken)
	}
	if len(ac.Token()) == 0 {
		slip.ErrorPanic(s, depth, "no vault token, provide :token, :approle, or set VAULT_TOKEN")
	}
	info, err := ac.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		if auth != nil {
			c.revokeToken(auth.ClientToken)
		}
		panic(err)
	}
	if auth == nil && info != nil {
		// A root token has a ttl of 0 and is not renewable.
		renewable, _ := info.TokenIsRenewable()
		ttl, _ := info.TokenTTL()
		if renewable && 0 < ttl {
			auth = &api.SecretAuth{ClientToken: ac.Token(), Renewable: true, LeaseDuration: int(ttl.Seconds())}
		}
	}
	c.renewable = auth != nil && auth.Renewable && 0 < auth.LeaseDuration
	if !spec.autoRenew {
		// The AppRole credentials are only kept to log in again.
		c.approle = nil
	}
	if c.renewable && spec.autoRenew {
		c.startWatcher(auth)
	}
	return c
}
