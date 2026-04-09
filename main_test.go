package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestSignHandlerEndToEnd drives the HTTP handler directly and then feeds
// the returned signature into `ssh-keygen -Y check-novalidate` to prove the
// full proxy pipeline produces a signature that ssh-keygen accepts.
func TestSignHandlerEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skipf("ssh-keygen not available: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}

	srv := httptest.NewServer(signHandler(signer, "git"))
	defer srv.Close()

	msg := []byte("end-to-end smoke test\n")

	resp, err := http.Post(srv.URL, "application/octet-stream", bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d: %s", resp.StatusCode, body)
	}
	sig, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	dir := t.TempDir()
	sigPath := filepath.Join(dir, "msg.sig")
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		t.Fatalf("write sig: %v", err)
	}

	cmd := exec.Command("ssh-keygen", "-Y", "check-novalidate", "-n", "git", "-s", sigPath)
	cmd.Stdin = bytes.NewReader(msg)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("check-novalidate failed: %v\nstdout: %s\nstderr: %s", err, out.String(), errb.String())
	}
}

// TestSignHandlerRejectsGet makes sure GET requests don't accidentally return
// a signature over an empty body.
func TestSignHandlerRejectsGet(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)

	srv := httptest.NewServer(signHandler(signer, "git"))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", resp.StatusCode)
	}
}

// TestPubkeyHandler verifies the /publickey endpoint returns the exact
// authorized_keys-format line for the loaded signer.
func TestPubkeyHandler(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)

	srv := httptest.NewServer(pubkeyHandler(signer))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	want := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if !bytes.Equal(got, want) {
		t.Fatalf("pubkey mismatch\nwant: %q\ngot:  %q", want, got)
	}

	// Round-trip: the line we got back must parse as the same public key.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(got)
	if err != nil {
		t.Fatalf("parse round-trip: %v", err)
	}
	if parsed.Type() != signer.PublicKey().Type() ||
		!bytes.Equal(parsed.Marshal(), signer.PublicKey().Marshal()) {
		t.Fatalf("round-tripped key does not match")
	}

	// Rejecting non-GET keeps this endpoint from getting misused.
	respPost, err := http.Post(srv.URL, "text/plain", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	respPost.Body.Close()
	if respPost.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("want 405 for POST, got %d", respPost.StatusCode)
	}
}

// startProxyStub spins up an httptest server that mirrors the real proxy's
// /sign and /publickey routes using the provided signer. Returns the server
// and the URL to pass to the shim as OP_SIGN_PROXY_URL.
func startProxyStub(t *testing.T, signer ssh.Signer) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/sign", signHandler(signer, "git"))
	mux.Handle("/publickey", pubkeyHandler(signer))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, srv.URL + "/sign"
}

// locateScript returns the path to scripts/op-git-sign.sh relative to this
// test file, skipping the test if it cannot be found.
func locateScript(t *testing.T) string {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	p := filepath.Join(filepath.Dir(testFile), "scripts", "op-git-sign.sh")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("script missing: %v", err)
	}
	return p
}

// requireShellTools skips the test if bash or curl are unavailable.
func requireShellTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available: %v", tool, err)
		}
	}
}

// TestOpGitSignScript drives the companion bash script against a local stub
// of the proxy to prove it parses ssh-keygen-style arguments correctly,
// forwards stdin to /sign, AND auto-populates a non-existent `-f <path>`
// with the public key fetched from /publickey on first use.
func TestOpGitSignScript(t *testing.T) {
	requireShellTools(t)
	scriptPath := locateScript(t)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)

	_, proxyURL := startProxyStub(t, signer)

	// Point -f at a path that does NOT exist yet. This mirrors how a user
	// would set `user.signingkey = ~/.cache/op-git-sign/signing.pub` and
	// have the shim materialize it on demand.
	cacheDir := filepath.Join(t.TempDir(), "cache", "op-git-sign")
	keyfile := filepath.Join(cacheDir, "signing.pub")
	if _, err := os.Stat(keyfile); !os.IsNotExist(err) {
		t.Fatalf("keyfile pre-exists or stat err: %v", err)
	}

	msg := []byte("commit payload via bash\n")

	cmd := exec.Command("bash", scriptPath, "-Y", "sign", "-n", "git", "-f", keyfile)
	cmd.Env = append(os.Environ(), "OP_SIGN_PROXY_URL="+proxyURL)
	cmd.Stdin = bytes.NewReader(msg)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("script failed: %v\nstderr: %s", err, errb.String())
	}

	sig := out.Bytes()
	if !bytes.HasPrefix(sig, []byte("-----BEGIN SSH SIGNATURE-----")) {
		t.Fatalf("script did not produce an armored signature:\n%s", sig)
	}
	if !strings.Contains(string(sig), "-----END SSH SIGNATURE-----") {
		t.Fatalf("missing end marker:\n%s", sig)
	}

	// The shim must have populated the cache file with the proxy's pubkey.
	cached, err := os.ReadFile(keyfile)
	if err != nil {
		t.Fatalf("keyfile was not populated: %v", err)
	}
	want := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if !bytes.Equal(cached, want) {
		t.Fatalf("cached pubkey mismatch\nwant: %q\ngot:  %q", want, cached)
	}

	// Second invocation must NOT overwrite the existing file (sanity check
	// that the auto-populate branch only fires when the file is missing).
	if err := os.WriteFile(keyfile, []byte("do not clobber\n"), 0o600); err != nil {
		t.Fatalf("rewrite keyfile: %v", err)
	}
	cmd2 := exec.Command("bash", scriptPath, "-Y", "sign", "-n", "git", "-f", keyfile)
	cmd2.Env = append(os.Environ(), "OP_SIGN_PROXY_URL="+proxyURL)
	cmd2.Stdin = bytes.NewReader(msg)
	cmd2.Stdout = io.Discard
	cmd2.Stderr = &errb
	if err := cmd2.Run(); err != nil {
		t.Fatalf("second invocation failed: %v\nstderr: %s", err, errb.String())
	}
	after, _ := os.ReadFile(keyfile)
	if string(after) != "do not clobber\n" {
		t.Fatalf("keyfile was clobbered on second invocation: %q", after)
	}

	if _, err := exec.LookPath("ssh-keygen"); err == nil {
		dir := t.TempDir()
		sigPath := filepath.Join(dir, "msg.sig")
		if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
			t.Fatalf("write sig: %v", err)
		}
		verify := exec.Command("ssh-keygen", "-Y", "check-novalidate", "-n", "git", "-s", sigPath)
		verify.Stdin = bytes.NewReader(msg)
		var verr bytes.Buffer
		verify.Stderr = &verr
		if err := verify.Run(); err != nil {
			t.Fatalf("script signature rejected by ssh-keygen: %v\nstderr: %s", err, verr.String())
		}
	}
}

// TestOpGitSignPubkeySubcommand exercises the `op-git-sign pubkey` bootstrap
// path, both the stdout form and the "write to <path>" form.
func TestOpGitSignPubkeySubcommand(t *testing.T) {
	requireShellTools(t)
	scriptPath := locateScript(t)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	_, proxyURL := startProxyStub(t, signer)

	want := ssh.MarshalAuthorizedKey(signer.PublicKey())

	// Form 1: `op-git-sign pubkey` → stdout.
	cmd := exec.Command("bash", scriptPath, "pubkey")
	cmd.Env = append(os.Environ(), "OP_SIGN_PROXY_URL="+proxyURL)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("pubkey subcommand failed: %v\nstderr: %s", err, errb.String())
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("stdout pubkey mismatch\nwant: %q\ngot:  %q", want, out.Bytes())
	}

	// Form 2: `op-git-sign pubkey <path>` → writes to <path>.
	dest := filepath.Join(t.TempDir(), "nested", "cache", "signing.pub")
	cmd2 := exec.Command("bash", scriptPath, "pubkey", dest)
	cmd2.Env = append(os.Environ(), "OP_SIGN_PROXY_URL="+proxyURL)
	cmd2.Stderr = &errb
	if err := cmd2.Run(); err != nil {
		t.Fatalf("pubkey <path> subcommand failed: %v\nstderr: %s", err, errb.String())
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file pubkey mismatch\nwant: %q\ngot:  %q", want, got)
	}
}
