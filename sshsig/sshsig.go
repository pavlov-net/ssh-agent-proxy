// Package sshsig implements the OpenSSH SSHSIG signature format in pure Go.
//
// The wire format follows PROTOCOL.sshsig from the OpenSSH source tree and
// produces output that is byte-identical to `ssh-keygen -Y sign` for
// deterministic signature schemes (Ed25519 and RSA with PKCS#1 v1.5).
package sshsig

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

const (
	magicPreamble = "SSHSIG"
	sigVersion    = uint32(1)

	// HashSHA512 is the default hash algorithm, matching ssh-keygen.
	HashSHA512 = "sha512"
	// HashSHA256 is also permitted by the SSHSIG spec.
	HashSHA256 = "sha256"

	armorBegin = "-----BEGIN SSH SIGNATURE-----\n"
	armorEnd   = "-----END SSH SIGNATURE-----\n"

	// armorWrapWidth is the line width used by OpenSSH's sshbuf_dtob64.
	armorWrapWidth = 70
)

// Sign produces an armored SSHSIG signature over message using the given
// signer, namespace, and the default SHA-512 hash algorithm.
func Sign(signer ssh.Signer, namespace string, message []byte) ([]byte, error) {
	return SignWithHash(rand.Reader, signer, namespace, HashSHA512, message)
}

// SignWithHash is like Sign but lets the caller specify the hash algorithm and
// an explicit random source.
func SignWithHash(randSource io.Reader, signer ssh.Signer, namespace, hashAlg string, message []byte) ([]byte, error) {
	if namespace == "" {
		return nil, fmt.Errorf("sshsig: namespace must not be empty")
	}
	hashed, err := hashMessage(hashAlg, message)
	if err != nil {
		return nil, err
	}

	toSign := buildSignedBlob(namespace, hashAlg, hashed)

	sig, err := signBlob(randSource, signer, toSign)
	if err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}

	raw := marshalSignature(signer.PublicKey(), namespace, hashAlg, sig)
	return armor(raw), nil
}

// hashMessage hashes message with the requested algorithm.
func hashMessage(hashAlg string, message []byte) ([]byte, error) {
	switch hashAlg {
	case HashSHA512:
		sum := sha512.Sum512(message)
		return sum[:], nil
	case HashSHA256:
		sum := sha256.Sum256(message)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("sshsig: unsupported hash algorithm %q", hashAlg)
	}
}

// buildSignedBlob constructs the pre-image that is fed to the SSH signer.
//
//	byte[6]   MAGIC_PREAMBLE
//	string    namespace
//	string    reserved
//	string    hash_algorithm
//	string    H(message)
func buildSignedBlob(namespace, hashAlg string, hash []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(magicPreamble)
	writeString(&buf, []byte(namespace))
	writeString(&buf, nil) // reserved, always empty
	writeString(&buf, []byte(hashAlg))
	writeString(&buf, hash)
	return buf.Bytes()
}

// signBlob signs the already-constructed signed-data buffer. For RSA keys it
// forces rsa-sha2-512 to match ssh-keygen's default behaviour; the base
// ssh.Signer implementation would otherwise fall back to SHA-1 (ssh-rsa),
// which is no longer accepted by modern verifiers.
func signBlob(rnd io.Reader, signer ssh.Signer, toSign []byte) (*ssh.Signature, error) {
	if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		as, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, fmt.Errorf("rsa signer does not implement AlgorithmSigner")
		}
		return as.SignWithAlgorithm(rnd, toSign, ssh.KeyAlgoRSASHA512)
	}
	return signer.Sign(rnd, toSign)
}

// marshalSignature produces the raw (unarmored) SSHSIG blob:
//
//	byte[6]   MAGIC_PREAMBLE
//	uint32    SIG_VERSION
//	string    publickey
//	string    namespace
//	string    reserved
//	string    hash_algorithm
//	string    signature  (itself string(format) || string(blob))
func marshalSignature(pub ssh.PublicKey, namespace, hashAlg string, sig *ssh.Signature) []byte {
	var buf bytes.Buffer
	buf.WriteString(magicPreamble)

	var v [4]byte
	binary.BigEndian.PutUint32(v[:], sigVersion)
	buf.Write(v[:])

	writeString(&buf, pub.Marshal())
	writeString(&buf, []byte(namespace))
	writeString(&buf, nil) // reserved
	writeString(&buf, []byte(hashAlg))

	// The signature field itself is an SSH signature wire blob:
	//   string(algorithm) || string(signature_bytes)
	var sigWire bytes.Buffer
	writeString(&sigWire, []byte(sig.Format))
	writeString(&sigWire, sig.Blob)
	writeString(&buf, sigWire.Bytes())

	return buf.Bytes()
}

// writeString writes an SSH-style length-prefixed byte string.
func writeString(buf *bytes.Buffer, s []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	buf.Write(l[:])
	buf.Write(s)
}

// armor wraps the raw SSHSIG blob in the PEM-like envelope that ssh-keygen
// emits. Unlike standard PEM, OpenSSH wraps the base64 payload at 70 columns
// (see sshbuf_dtob64 in the OpenSSH source).
func armor(raw []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(raw)

	var out bytes.Buffer
	out.Grow(len(armorBegin) + len(encoded) + len(encoded)/armorWrapWidth + len(armorEnd) + 1)
	out.WriteString(armorBegin)
	for i := 0; i < len(encoded); i += armorWrapWidth {
		end := i + armorWrapWidth
		if end > len(encoded) {
			end = len(encoded)
		}
		out.WriteString(encoded[i:end])
		out.WriteByte('\n')
	}
	out.WriteString(armorEnd)
	return out.Bytes()
}
