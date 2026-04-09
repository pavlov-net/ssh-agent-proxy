// op-sign-proxy is a tiny HTTP server that signs arbitrary bytes with an SSH
// private key fetched from 1Password at startup. It exposes a single
// POST /sign endpoint that returns an armored SSHSIG signature suitable for
// use as a git SSH signature (namespace "git").
//
// Environment variables:
//
//	OP_SERVICE_ACCOUNT_TOKEN  1Password service-account token (required)
//	OP_SSH_KEY_REF            op://vault/item/field reference to the private
//	                          key, e.g. op://Personal/Git Signing/private key
//	                          (required)
//	OP_SIGN_PROXY_ADDR        listen address (default 127.0.0.1:7221)
//	OP_SIGN_PROXY_NAMESPACE   SSHSIG namespace (default "git")
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
	"golang.org/x/crypto/ssh"

	"github.com/stuartparmenter/op-sign-proxy/sshsig"
)

const (
	defaultAddr      = "127.0.0.1:7221"
	defaultNamespace = "git"
	integrationName  = "op-sign-proxy"
	integrationVer   = "v0.1.0"
	maxRequestBody   = 16 << 20 // 16 MiB, plenty for a git commit payload
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("op-sign-proxy: %v", err)
	}
}

func run() error {
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if token == "" {
		return errors.New("OP_SERVICE_ACCOUNT_TOKEN is not set")
	}
	ref := os.Getenv("OP_SSH_KEY_REF")
	if ref == "" {
		return errors.New("OP_SSH_KEY_REF is not set (e.g. op://Vault/Item/private key)")
	}

	addr := os.Getenv("OP_SIGN_PROXY_ADDR")
	if addr == "" {
		addr = defaultAddr
	}
	namespace := os.Getenv("OP_SIGN_PROXY_NAMESPACE")
	if namespace == "" {
		namespace = defaultNamespace
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	signer, err := loadSigner(ctx, token, ref)
	if err != nil {
		return fmt.Errorf("loading signing key: %w", err)
	}
	log.Printf("loaded %s signing key (fingerprint %s)",
		signer.PublicKey().Type(), ssh.FingerprintSHA256(signer.PublicKey()))

	srv := newServer(addr, signer, namespace)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Printf("listening on %s (namespace %q)", listener.Addr(), namespace)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		log.Printf("shutdown signal received")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// loadSigner fetches the SSH private key from 1Password using the service
// account token and parses it into an ssh.Signer. The secret reference must
// point at the private-key field of an SSH Key item (or a password-style
// field containing an OpenSSH-formatted key).
func loadSigner(ctx context.Context, token, ref string) (ssh.Signer, error) {
	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo(integrationName, integrationVer),
	)
	if err != nil {
		return nil, fmt.Errorf("1password client: %w", err)
	}

	pem, err := client.Secrets().Resolve(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", ref, err)
	}

	signer, err := ssh.ParsePrivateKey([]byte(pem))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return signer, nil
}

// newServer builds the signing HTTP server with sensible timeouts.
func newServer(addr string, signer ssh.Signer, namespace string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", signHandler(signer, namespace))
	mux.HandleFunc("/publickey", pubkeyHandler(signer))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// signHandler returns an http.HandlerFunc that reads the raw request body and
// returns an armored SSHSIG signature over it.
func signHandler(signer ssh.Signer, namespace string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(body) == 0 {
			http.Error(w, "empty request body", http.StatusBadRequest)
			return
		}

		sig, err := sshsig.Sign(signer, namespace, body)
		if err != nil {
			log.Printf("sign error: %v", err)
			http.Error(w, "sign failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-ssh-signature")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(sig)))
		_, _ = w.Write(sig)
	}
}

// pubkeyHandler returns the OpenSSH-format public key line for the loaded
// signing key. Exposing this lets the container-side shim fetch and cache the
// public key on demand, so the container's git config never needs to hardcode
// a specific key (see scripts/op-git-sign.sh).
func pubkeyHandler(signer ssh.Signer) http.HandlerFunc {
	line := ssh.MarshalAuthorizedKey(signer.PublicKey())
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(line)))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(line)
	}
}
