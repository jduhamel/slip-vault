// Copyright (c) 2026, Joe Duhamel, All rights reserved.

package vault_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ohler55/slip"

	// Blank import so the vault-connect, vault-kv-*, secret, etc. functions register.
	_ "github.com/jduhamel/slip-vault/vault"
)

const (
	vaultBinPath     = "/opt/homebrew/bin/vault"
	approleRole      = "sliptest"
	approleShortRole = "sliptest-short"
	approleMount     = "approle"
	rootToken        = "root"
	kvMount          = "secret"
	healthTimeout    = 10 * time.Second
)

var (
	// vaultAddr is the host:port (no scheme) the dev server is listening on.
	vaultAddr string

	// vaultAvailable is true when the vault binary was found and the dev
	// server started successfully. Integration tests should call
	// requireVault(t) to skip when this is false.
	vaultAvailable bool

	// approleRoleID and approleSecretID are populated during setup when
	// vaultAvailable is true, for use by the :approle connect test.
	approleRoleID   string
	approleSecretID string

	// approleShortRoleID and approleShortSecretID are populated during setup
	// for the short-TTL role used by the auto-renew tests (token_ttl=4s,
	// token_max_ttl=10s).
	approleShortRoleID   string
	approleShortSecretID string

	// vaultToken is the root token for the server under test.
	vaultToken = rootToken

	// runID makes KV paths unique per test run so reruns against a
	// persistent (e.g. docker compose) server don't collide.
	runID = newRunID()
)

func newRunID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func TestMain(m *testing.M) {
	os.Exit(wrapRun(m))
}

func wrapRun(m *testing.M) (status int) {
	// An external server (e.g. `make vault-up` with docker compose) takes
	// precedence over spawning a dev server.
	if ext := os.Getenv("VAULT_TEST_ADDR"); ext != "" {
		vaultAddr = strings.TrimPrefix(strings.TrimPrefix(ext, "http://"), "https://")
		if tok := os.Getenv("VAULT_TEST_TOKEN"); tok != "" {
			vaultToken = tok
		}
		vaultAvailable = true
		if err := enableApprole(); err != nil {
			fmt.Printf("*-*-* failed to enable approle auth: %s\n", err)
		}
		if err := enableShortApprole(); err != nil {
			fmt.Printf("*-*-* failed to enable short-TTL approle role: %s\n", err)
		}
		return m.Run()
	}
	binPath, err := exec.LookPath(vaultBinPath)
	if err != nil {
		if binPath, err = exec.LookPath("vault"); err != nil {
			fmt.Printf("*-*-* vault binary not found (%s); integration tests will be skipped\n", err)
			return m.Run()
		}
	}

	reapStaleServers()
	cmd, addr, err := startVaultDevServer(binPath)
	if err != nil {
		fmt.Printf("*-*-* failed to start vault dev server: %s\n", err)
		return m.Run()
	}
	vaultAddr = addr
	vaultAvailable = true

	defer func() {
		if rec := recover(); rec != nil {
			fmt.Printf("*-*-* panic: %s\n", rec)
			status = 1
		}
		killGroup(cmd)
	}()

	// On a server started here approle setup must work, otherwise the
	// approle and renewal tests would skip silently and the run looks green.
	if err = enableApprole(); err != nil {
		fmt.Printf("*-*-* failed to enable approle auth: %s\n", err)
		return 1
	}
	if err = enableShortApprole(); err != nil {
		fmt.Printf("*-*-* failed to enable short-TTL approle role: %s\n", err)
		return 1
	}

	status = m.Run()
	return
}

// killGroup kills the dev server and anything it spawned. The server runs in
// its own process group so no orphan survives the test binary.
func killGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_, _ = cmd.Process.Wait()
	_ = os.Remove(pidFile(cmd.Process.Pid))
}

// pidDir holds one file per running dev server, named for the server pid and
// containing the pid of the test binary that started it. A test that panics
// exits without running TestMain's defers so the next run uses these files to
// reap servers whose test binary is gone.
func pidDir() string {
	return filepath.Join(os.TempDir(), "slip-vault-test")
}

func pidFile(serverPid int) string {
	return filepath.Join(pidDir(), strconv.Itoa(serverPid)+".pid")
}

func recordServer(serverPid int) {
	if err := os.MkdirAll(pidDir(), 0o700); err == nil {
		_ = os.WriteFile(pidFile(serverPid), []byte(strconv.Itoa(os.Getpid())), 0o600)
	}
}

// reapStaleServers kills dev servers left behind by test binaries that no
// longer exist. A pid is only killed if it is still a vault dev server.
func reapStaleServers() {
	entries, err := os.ReadDir(pidDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		serverPid, err := strconv.Atoi(strings.TrimSuffix(e.Name(), ".pid"))
		if err != nil {
			continue
		}
		path := filepath.Join(pidDir(), e.Name())
		owner, _ := os.ReadFile(path)
		if ownerPid, err := strconv.Atoi(string(owner)); err == nil && syscall.Kill(ownerPid, 0) == nil {
			continue // the test binary that started it is still running
		}
		out, _ := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(serverPid)).Output()
		if strings.Contains(string(out), "server -dev -dev-no-store-token") {
			fmt.Printf("*-*-* reaping stale vault dev server %d\n", serverPid)
			_ = syscall.Kill(-serverPid, syscall.SIGKILL)
		}
		_ = os.Remove(path)
	}
}

// startVaultDevServer launches `vault server -dev` on a free port and waits
// for it to answer sys/health.
func startVaultDevServer(binPath string) (cmd *exec.Cmd, addr string, err error) {
	addr = fmt.Sprintf("127.0.0.1:%d", availablePort())
	// -dev-no-store-token keeps the dev server from overwriting the user's
	// ~/.vault-token. HOME is also pointed at a scratch directory as a second
	// guard in case the token helper is invoked anyway.
	home, err := os.MkdirTemp("", "slip-vault-home-")
	if err != nil {
		return
	}
	cmd = exec.Command(binPath, "server", "-dev",
		"-dev-no-store-token",
		"-dev-root-token-id="+rootToken,
		"-dev-listen-address="+addr)
	cmd.Env = append(scrubbedEnv(), "HOME="+home)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = cmd.Start(); err != nil {
		return
	}
	recordServer(cmd.Process.Pid)
	healthURL := "http://" + addr + "/v1/sys/health"
	deadline := time.Now().Add(healthTimeout)
	for time.Now().Before(deadline) {
		resp, herr := http.Get(healthURL)
		if herr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	killGroup(cmd)
	err = fmt.Errorf("vault dev server at %s did not become healthy within %s", addr, healthTimeout)
	return
}

// scrubbedEnv returns the environment without HOME or any VAULT_* variables.
func scrubbedEnv() (env []string) {
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "VAULT_") || strings.HasPrefix(kv, "HOME=") {
			continue
		}
		env = append(env, kv)
	}
	return
}

func availablePort() int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

// enableApprole mounts the approle auth method, creates a role, and fetches
// its role-id and secret-id, storing them in the package vars above.
func enableApprole() error {
	if _, err := vaultAPI(http.MethodPost, "/v1/sys/auth/"+approleMount, map[string]any{
		"type": "approle",
	}); err != nil && !strings.Contains(err.Error(), "path is already in use") {
		return err
	}
	if _, err := vaultAPI(http.MethodPost, "/v1/auth/"+approleMount+"/role/"+approleRole, map[string]any{
		"token_policies": "default",
		"token_ttl":      "1h",
		"token_max_ttl":  "4h",
	}); err != nil {
		return err
	}
	roleResp, err := vaultAPI(http.MethodGet, "/v1/auth/"+approleMount+"/role/"+approleRole+"/role-id", nil)
	if err != nil {
		return err
	}
	data, _ := roleResp["data"].(map[string]any)
	roleID, _ := data["role_id"].(string)
	if roleID == "" {
		return fmt.Errorf("role-id response missing data.role_id: %v", roleResp)
	}
	secretResp, err := vaultAPI(http.MethodPost, "/v1/auth/"+approleMount+"/role/"+approleRole+"/secret-id", nil)
	if err != nil {
		return err
	}
	data, _ = secretResp["data"].(map[string]any)
	secretID, _ := data["secret_id"].(string)
	if secretID == "" {
		return fmt.Errorf("secret-id response missing data.secret_id: %v", secretResp)
	}
	approleRoleID = roleID
	approleSecretID = secretID
	return nil
}

// enableShortApprole creates the short-TTL role used by the auto-renew
// tests: token_ttl=4s, token_max_ttl=10s. It reuses the approle auth mount
// enabled by enableApprole (mounting is idempotent so the order does not
// matter).
func enableShortApprole() error {
	if _, err := vaultAPI(http.MethodPost, "/v1/sys/auth/"+approleMount, map[string]any{
		"type": "approle",
	}); err != nil && !strings.Contains(err.Error(), "path is already in use") {
		return err
	}
	if _, err := vaultAPI(http.MethodPost, "/v1/auth/"+approleMount+"/role/"+approleShortRole, map[string]any{
		"token_policies": "default",
		"token_ttl":      "4s",
		"token_max_ttl":  "10s",
	}); err != nil {
		return err
	}
	roleResp, err := vaultAPI(http.MethodGet, "/v1/auth/"+approleMount+"/role/"+approleShortRole+"/role-id", nil)
	if err != nil {
		return err
	}
	data, _ := roleResp["data"].(map[string]any)
	roleID, _ := data["role_id"].(string)
	if roleID == "" {
		return fmt.Errorf("role-id response missing data.role_id: %v", roleResp)
	}
	secretResp, err := vaultAPI(http.MethodPost, "/v1/auth/"+approleMount+"/role/"+approleShortRole+"/secret-id", nil)
	if err != nil {
		return err
	}
	data, _ = secretResp["data"].(map[string]any)
	secretID, _ := data["secret_id"].(string)
	if secretID == "" {
		return fmt.Errorf("secret-id response missing data.secret_id: %v", secretResp)
	}
	approleShortRoleID = roleID
	approleShortSecretID = secretID
	return nil
}

func vaultAPI(method, path string, body map[string]any) (result map[string]any, err error) {
	var reader io.Reader
	if body != nil {
		var b []byte
		if b, err = json.Marshal(body); err != nil {
			return
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://"+vaultAddr+path, reader)
	if err != nil {
		return
	}
	req.Header.Set("X-Vault-Token", vaultToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		buf, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, string(buf))
	}
	if resp.ContentLength == 0 {
		return map[string]any{}, nil
	}
	dec := json.NewDecoder(resp.Body)
	result = map[string]any{}
	if err = dec.Decode(&result); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return result, nil
}

// requireVault skips the calling test when no vault dev server is running.
func requireVault(t *testing.T) {
	t.Helper()
	if !vaultAvailable {
		t.Skip("vault binary not available on PATH; skipping integration test")
	}
}

// requireApprole skips the calling test when approle auth was not set up
// during TestMain (e.g. because vault itself was unavailable).
func requireApprole(t *testing.T) {
	t.Helper()
	requireVault(t)
	if approleRoleID == "" || approleSecretID == "" {
		t.Skip("approle auth was not enabled during setup; skipping")
	}
}

// requireShortApprole skips the calling test when the short-TTL approle role
// was not set up during TestMain.
func requireShortApprole(t *testing.T) {
	t.Helper()
	requireVault(t)
	if approleShortRoleID == "" || approleShortSecretID == "" {
		t.Skip("short-TTL approle role was not enabled during setup; skipping")
	}
}

// clearVaultEnv clears the VAULT_* environment variables that vault-connect
// and the underlying api.Client fall back to, for the duration of the
// calling test, so ambient environment state (e.g. a developer's shell, or a
// previous test's t.Setenv) cannot influence a test that expects explicit
// options to be the only source of truth. It uses os.Unsetenv rather than
// t.Setenv("", "") because an empty string is still a "set" value to some
// environment readers; this also means callers must not combine it with
// t.Parallel().
func clearVaultEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"VAULT_ADDR", "VAULT_TOKEN", "VAULT_AGENT_ADDR", "VAULT_NAMESPACE"} {
		clearEnv(t, k)
	}
}

// clearEnv unsets a single environment variable for the duration of the
// calling test, restoring its prior value (or absence) on cleanup.
func clearEnv(t *testing.T, key string) {
	t.Helper()
	orig, had := os.LookupEnv(key)
	_ = os.Unsetenv(key)
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, orig)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

// randomCanary returns a value that only exists at test-runtime, never typed
// into Lisp source, for use as a leak-detection needle: tests search error
// messages and printed output for this string to confirm it never appears
// unless explicitly requested via secret-value.
func randomCanary(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to generate canary: %s", err)
	}
	return prefix + hex.EncodeToString(b)
}

// panicMessage evaluates src against scope (a fresh Scope if nil) and
// returns the message text of the panic it is expected to raise. It fails
// the test if src does not panic. Unlike sliptest.Function's Panics field,
// this exposes the message so tests can assert on its content, e.g. to
// confirm a leak canary never appears in an error.
func panicMessage(t *testing.T, scope *slip.Scope, src string) (msg string) {
	t.Helper()
	if scope == nil {
		scope = slip.NewScope()
	}
	panicked := func() (recovered bool) {
		defer func() {
			r := recover()
			if r == nil {
				return
			}
			recovered = true
			switch rv := r.(type) {
			case *slip.Panic:
				msg = rv.Error()
			case slip.Instance:
				if m, has := rv.SlotValue(slip.Symbol("message")); has {
					if ss, ok := m.(slip.String); ok {
						msg = string(ss)
					} else {
						msg = slip.ObjectString(m)
					}
				} else {
					msg = slip.ObjectString(rv)
				}
			case error:
				msg = rv.Error()
			default:
				msg = fmt.Sprintf("%v", rv)
			}
		}()
		code, provs := slip.ReadProv([]byte(src), scope, t.Name(), nil)
		code.CompileWithProvenance(provs)
		code.Eval(scope, nil)
		return false
	}()
	if !panicked {
		t.Fatalf("expected a panic, got none for: %s", src)
	}
	return
}

// vaultAddrURL returns the dev server address with an http:// scheme, as
// expected by the :address connect option.
func vaultAddrURL() string {
	return "http://" + vaultAddr
}

// connectedScope returns a Scope with a "v" variable bound to a vault-client
// connected to the dev server with the root token.
func connectedScope(t *testing.T) *slip.Scope {
	t.Helper()
	requireVault(t)
	clearVaultEnv(t)
	scope := slip.NewScope()
	scope.Let(slip.Symbol("v"), nil)
	src := fmt.Sprintf(`(setq v (vault-connect :address %q :token %q))`, vaultAddrURL(), vaultToken)
	result := slip.ReadString(src, scope).Eval(scope, nil)
	if result == nil {
		t.Fatalf("vault-connect returned nil for %s", src)
	}
	return scope
}

// uniquePath returns a KV path unique to the calling test, so tests can run
// without stepping on each other's data.
func uniquePath(t *testing.T) string {
	t.Helper()
	r := strings.NewReplacer("/", "-", " ", "_")
	return "test-" + runID + "-" + r.Replace(t.Name())
}
