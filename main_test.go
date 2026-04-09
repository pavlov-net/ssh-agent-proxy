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

// TestOpGitSignScript drives the companion bash script against a local stub
// of the proxy to prove it parses ssh-keygen-style arguments correctly and
// forwards stdin to /sign.
func TestOpGitSignScript(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skipf("curl not available: %v", err)
	}

	// Locate the script relative to this test file.
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	scriptPath := filepath.Join(filepath.Dir(testFile), "scripts", "op-git-sign.sh")
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("script missing: %v", err)
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)

	mux := http.NewServeMux()
	mux.Handle("/sign", signHandler(signer, "git"))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	proxyURL := srv.URL + "/sign"

	msg := []byte("commit payload via bash\n")

	cmd := exec.Command("bash", scriptPath, "-Y", "sign", "-n", "git", "-f", "/nonexistent/key")
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
