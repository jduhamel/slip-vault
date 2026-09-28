// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ohler55/slip"
	"github.com/ohler55/slip/sliptest"
)

func TestConnectAddressAndToken(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(vault-connect :address %q :token %q)`, vaultAddrURL(), rootToken),
		Expect: `/#<vault-client [0-9a-f]+>/`,
	}).Test(t)
}

func TestConnectAddressAndTokenCanCallMethod(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(let ((v (vault-connect :address %q :token %q)))
                              (and (send v :token-lookup-self) t))`, vaultAddrURL(), rootToken),
		Expect: `t`,
	}).Test(t)
}

func TestConnectBadTokenErrorsOnFirstCall(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	// vault-connect itself should not need to validate the token (the real
	// Vault client does not authenticate until the first request), but the
	// combined connect + first-call expression below must error somewhere
	// in that pipeline.
	(&sliptest.Function{
		Source: fmt.Sprintf(`(let ((v (vault-connect :address %q :token "not-a-real-token")))
                              (send v :token-lookup-self))`, vaultAddrURL()),
		Panics: true,
	}).Test(t)
}

func TestConnectUnreachableAddressRespectsTimeout(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)

	done := make(chan struct{})
	var recovered any
	go func() {
		defer close(done)
		defer func() { recovered = recover() }()
		scope := slip.NewScope()
		// 192.0.2.1 is TEST-NET-1 (RFC 5737): reserved for documentation,
		// never routable, so the connection attempt should reliably hang
		// until :timeout cuts it off rather than being refused instantly.
		src := `(let ((v (vault-connect :address "http://192.0.2.1:8200" :token "root" :timeout 1)))
                  (send v :token-lookup-self))`
		code, provs := slip.ReadProv([]byte(src), scope, t.Name(), nil)
		code.CompileWithProvenance(provs)
		code.Eval(scope, nil)
	}()
	select {
	case <-done:
		if recovered == nil {
			t.Fatal("expected connecting to an unreachable address to error, but it succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("vault-connect with :timeout 1 against an unreachable address did not return within 5s; " +
			":timeout may not be honored")
	}
}

func TestConnectApprole(t *testing.T) {
	requireApprole(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(let ((v (vault-connect :address %q :approle (list %q %q))))
                              (and (send v :token-lookup-self) t))`,
			vaultAddrURL(), approleRoleID, approleSecretID),
		Expect: `t`,
	}).Test(t)
}

func TestConnectApproleBadSecretID(t *testing.T) {
	requireApprole(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(vault-connect :address %q :approle (list %q "not-a-real-secret-id"))`,
			vaultAddrURL(), approleRoleID),
		Panics: true,
	}).Test(t)
}

func TestConnectTimeoutWrongTypeIsTypeError(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source:    fmt.Sprintf(`(vault-connect :address %q :token %q :timeout "not-a-number")`, vaultAddrURL(), rootToken),
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestConnectNamespaceWrongTypeIsTypeError(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source:    fmt.Sprintf(`(vault-connect :address %q :token %q :namespace 123)`, vaultAddrURL(), rootToken),
		PanicType: slip.TypeErrorSymbol,
	}).Test(t)
}

func TestConnectEnvDefaults(t *testing.T) {
	requireVault(t)
	t.Setenv("VAULT_ADDR", vaultAddrURL())
	t.Setenv("VAULT_TOKEN", rootToken)
	(&sliptest.Function{
		Source: `(let ((v (vault-connect)))
                   (and (send v :token-lookup-self) t))`,
		Expect: `t`,
	}).Test(t)
}

func TestConnectEnvDefaultsExplicitOverridesEnv(t *testing.T) {
	requireVault(t)
	t.Setenv("VAULT_ADDR", "http://192.0.2.1:1")
	t.Setenv("VAULT_TOKEN", "bogus-env-token")
	(&sliptest.Function{
		Source: fmt.Sprintf(`(let ((v (vault-connect :address %q :token %q)))
                              (and (send v :token-lookup-self) t))`, vaultAddrURL(), rootToken),
		Expect: `t`,
	}).Test(t)
}

// TestConnectVaultAgentAddrDoesNotOverrideExplicitAddress covers the round-2
// review item: VAULT_AGENT_ADDR set to a bogus address must not override an
// explicit :address. The underlying api.Client prefers AgentAddress over
// Address once ReadEnvironment has populated it (see
// hashicorp/vault/api client.go NewClient, "if c.AgentAddress != ..."), so
// vault-connect must clear or ignore it when :address is given explicitly.
// The bogus address refuses the connection immediately (nothing listens on
// 127.0.0.1:1) rather than hanging, so a failure here shows up as a panic,
// not a timeout.
func TestConnectVaultAgentAddrDoesNotOverrideExplicitAddress(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	t.Setenv("VAULT_AGENT_ADDR", "http://127.0.0.1:1")
	(&sliptest.Function{
		Source: fmt.Sprintf(`(let ((v (vault-connect :address %q :token %q)))
                              (and (send v :token-lookup-self) t))`, vaultAddrURL(), rootToken),
		Expect: `t`,
	}).Test(t)
}

// TestConnectTokenAsSecretObject covers passing an already-wrapped secret
// (rather than a plain string) for :token, the *Secret branch of
// stringOrSecret (util.go).
func TestConnectTokenAsSecretObject(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(let ((v (vault-connect :address %q :token (make-secret %q))))
                              (and (send v :token-lookup-self) t))`, vaultAddrURL(), rootToken),
		Expect: `t`,
	}).Test(t)
}

// --- TLS option coverage --------------------------------------------------

func TestConnectCaCertMissingFileErrors(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(vault-connect :address %q :token %q :ca-cert "/nonexistent/ca.pem")`,
			vaultAddrURL(), rootToken),
		Panics: true,
	}).Test(t)
}

func TestConnectClientCertMissingFileErrors(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(vault-connect :address %q :token %q :client-cert "/nonexistent/client.pem")`,
			vaultAddrURL(), rootToken),
		Panics: true,
	}).Test(t)
}

func TestConnectClientKeyMissingFileErrors(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(vault-connect :address %q :token %q :client-key "/nonexistent/client-key.pem")`,
			vaultAddrURL(), rootToken),
		Panics: true,
	}).Test(t)
}

// TestConnectTlsSkipVerifyOverHttpStillConnects exercises the hasTLS branch
// of connect() (ConfigureTLS is called) even though the dev server is plain
// http, so the TLS config is prepared but never used on the wire. It should
// not error just because TLS was configured.
func TestConnectTlsSkipVerifyOverHttpStillConnects(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	(&sliptest.Function{
		Source: fmt.Sprintf(`(let ((v (vault-connect :address %q :token %q :tls-skip-verify t)))
                              (and (send v :token-lookup-self) t))`, vaultAddrURL(), rootToken),
		Expect: `t`,
	}).Test(t)
}

// --- leak-safe error messages ----------------------------------------------
//
// These use panicMessage rather than sliptest's Panics/PanicType fields so
// the error text itself can be inspected for the canary. The canary is bound
// into the scope at runtime (never typed into the Lisp source) per the
// review's leak-canary rule.

// TestConnectApproleBadLengthDoesNotLeakSecretID covers the connect.go
// comment "the value is not included in the error as it may hold the
// secret-id": a badly-shaped :approle list (too many elements here) must
// raise a generic error that never echoes the list's contents, even though
// one of those elements holds what looks like a secret.
func TestConnectApproleBadLengthDoesNotLeakSecretID(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	canary := randomCanary(t, "sekrit-")
	scope := slip.NewScope()
	scope.Let(slip.Symbol("canary"), slip.String(canary))
	msg := panicMessage(t, scope, fmt.Sprintf(
		`(vault-connect :address %q :approle (list "role-id" canary "approle" "one-too-many"))`,
		vaultAddrURL()))
	if strings.Contains(msg, canary) {
		t.Fatalf("a bad-length :approle list leaked the secret-id-shaped element into the error: %q", msg)
	}
}

// TestConnectApproleWrongTypeSecretIDDoesNotLeakValue covers the
// stringOrSecret branch inside :approle's element check: a correctly-sized
// list whose secret-id element is a wrong type (a list wrapping something
// secret-shaped) must not leak that wrapped value into the type-error
// message.
func TestConnectApproleWrongTypeSecretIDDoesNotLeakValue(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	canary := randomCanary(t, "sekrit-")
	scope := slip.NewScope()
	scope.Let(slip.Symbol("canary"), slip.String(canary))
	msg := panicMessage(t, scope, fmt.Sprintf(
		`(vault-connect :address %q :approle (list "role-id" (list canary)))`, vaultAddrURL()))
	if strings.Contains(msg, canary) {
		t.Fatalf("a wrong-typed :approle secret-id containing a secret-shaped value leaked it into the error: %q", msg)
	}
}

// TestConnectTokenWrongTypeDoesNotLeakEmbeddedCanary covers the same
// principle for :token: giving it a value of the wrong type (a list) that
// happens to contain something secret-shaped must not echo that value's
// contents into the resulting type-error message.
func TestConnectTokenWrongTypeDoesNotLeakEmbeddedCanary(t *testing.T) {
	requireVault(t)
	clearVaultEnv(t)
	canary := randomCanary(t, "sekrit-")
	scope := slip.NewScope()
	scope.Let(slip.Symbol("canary"), slip.String(canary))
	msg := panicMessage(t, scope, fmt.Sprintf(
		`(vault-connect :address %q :token (list canary))`, vaultAddrURL()))
	if strings.Contains(msg, canary) {
		t.Fatalf("a wrong-typed :token containing a secret-shaped value leaked it into the error: %q", msg)
	}
}
