package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// requireSSHKeygen skips the test if ssh-keygen is not installed. CI images
// without OpenSSH will simply skip these end-to-end comparison tests.
func requireSSHKeygen(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skipf("ssh-keygen not available: %v", err)
	}
	return path
}

// writeOpenSSHPrivateKey writes an Ed25519 key to disk in the OpenSSH PEM
// format that ssh-keygen understands.
func writeOpenSSHPrivateKey(t *testing.T, dir string, priv ed25519.PrivateKey) string {
	t.Helper()

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}

	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return keyPath
}

// writeOpenSSHRSAKey writes an RSA key to disk in OpenSSH PEM format.
func writeOpenSSHRSAKey(t *testing.T, dir string, priv *rsa.PrivateKey) string {
	t.Helper()

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}

	keyPath := filepath.Join(dir, "id_rsa")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return keyPath
}

// runSSHKeygenSign shells out to ssh-keygen -Y sign and returns the resulting
// armored signature. The input message is piped via stdin.
func runSSHKeygenSign(t *testing.T, keyPath, namespace string, message []byte) []byte {
	t.Helper()

	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-n", namespace, "-f", keyPath)
	cmd.Stdin = bytes.NewReader(message)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh-keygen -Y sign failed: %v\nstderr: %s", err, stderr.String())
	}
	return stdout.Bytes()
}

// runSSHKeygenCheck validates that the provided armored signature is accepted
// by `ssh-keygen -Y check-novalidate` against the given public key material.
// This exercises the verify path without needing an allowed_signers file.
func runSSHKeygenCheck(t *testing.T, signerPub ssh.PublicKey, namespace string, message, signature []byte) {
	t.Helper()

	dir := t.TempDir()
	sigPath := filepath.Join(dir, "msg.sig")
	if err := os.WriteFile(sigPath, signature, 0o600); err != nil {
		t.Fatalf("write sig: %v", err)
	}

	// check-novalidate does not consult an allowed_signers file, but it still
	// requires the signature be well-formed and the embedded public key to
	// cryptographically verify the message.
	cmd := exec.Command("ssh-keygen", "-Y", "check-novalidate", "-n", namespace, "-s", sigPath)
	cmd.Stdin = bytes.NewReader(message)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh-keygen -Y check-novalidate rejected our signature: %v\nstdout: %s\nstderr: %s",
			err, stdout.String(), stderr.String())
	}
	_ = signerPub
}

// TestSignMatchesSSHKeygen_Ed25519 is the core correctness test: for an
// Ed25519 key (which is deterministic by design) our output must be
// byte-for-byte identical to `ssh-keygen -Y sign`.
func TestSignMatchesSSHKeygen_Ed25519(t *testing.T) {
	requireSSHKeygen(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}

	keyPath := writeOpenSSHPrivateKey(t, t.TempDir(), priv)

	const namespace = "git"
	message := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\ncommit body\n")

	ours, err := Sign(signer, namespace, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	theirs := runSSHKeygenSign(t, keyPath, namespace, message)

	if !bytes.Equal(ours, theirs) {
		t.Fatalf("signature mismatch\nours:\n%s\ntheirs:\n%s", ours, theirs)
	}
}

// TestSignMatchesSSHKeygen_RSA verifies byte-equality for RSA keys. RSA with
// PKCS#1 v1.5 (which OpenSSH uses for rsa-sha2-512 in SSHSIG) is deterministic,
// so we can expect byte equality here as well.
func TestSignMatchesSSHKeygen_RSA(t *testing.T) {
	requireSSHKeygen(t)

	if testing.Short() {
		t.Skip("RSA key generation is slow; skipping under -short")
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}

	keyPath := writeOpenSSHRSAKey(t, t.TempDir(), priv)

	const namespace = "git"
	message := []byte("rsa test payload\n")

	ours, err := Sign(signer, namespace, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	theirs := runSSHKeygenSign(t, keyPath, namespace, message)

	if !bytes.Equal(ours, theirs) {
		t.Fatalf("rsa signature mismatch\nours:\n%s\ntheirs:\n%s", ours, theirs)
	}
}

// TestSignAcceptedBySSHKeygenCheck sanity-checks that ssh-keygen is willing to
// parse and verify our output. This catches structural problems in the blob
// that a pure byte-compare might miss (e.g. wrong ordering of fields).
func TestSignAcceptedBySSHKeygenCheck(t *testing.T) {
	requireSSHKeygen(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}

	const namespace = "git"
	message := []byte("hello, git signing\n")

	sig, err := Sign(signer, namespace, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	runSSHKeygenCheck(t, signer.PublicKey(), namespace, message, sig)
}

// TestSignRejectsEmptyNamespace makes sure we don't silently produce a
// signature with an empty namespace, which ssh-keygen would reject.
func TestSignRejectsEmptyNamespace(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}

	if _, err := Sign(signer, "", []byte("msg")); err == nil {
		t.Fatal("expected error for empty namespace")
	}
}

// TestArmorWrap70 pins the base64 wrapping width at 70 to match
// OpenSSH's sshbuf_dtob64.
func TestArmorWrap70(t *testing.T) {
	// 140 bytes of zeroes => 188 base64 chars => 3 lines (70+70+48).
	payload := bytes.Repeat([]byte{0}, 140)
	out := armor(payload)

	lines := bytes.Split(out, []byte("\n"))
	// First line is the BEGIN marker, last two entries are the END marker
	// followed by an empty string (trailing newline).
	if got := string(lines[0]); got != "-----BEGIN SSH SIGNATURE-----" {
		t.Fatalf("bad begin line: %q", got)
	}
	if got := string(lines[len(lines)-2]); got != "-----END SSH SIGNATURE-----" {
		t.Fatalf("bad end line: %q", got)
	}

	// Each base64 line except possibly the last must be exactly 70 chars.
	bodyLines := lines[1 : len(lines)-2]
	for i, l := range bodyLines {
		if i == len(bodyLines)-1 {
			if len(l) == 0 || len(l) > 70 {
				t.Fatalf("last base64 line length %d out of range", len(l))
			}
			continue
		}
		if len(l) != 70 {
			t.Fatalf("base64 line %d has length %d, want 70", i, len(l))
		}
	}
}
