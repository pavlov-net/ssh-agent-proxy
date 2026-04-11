use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const HASH_SHA512: &str = "sha512";
pub const HASH_SHA256: &str = "sha256";

const MAGIC_PREAMBLE: &[u8] = b"SSHSIG";
const SIG_VERSION: u32 = 1;
const ARMOR_LINE_LEN: usize = 70;
const BEGIN_MARKER: &str = "-----BEGIN SSH SIGNATURE-----";
const END_MARKER: &str = "-----END SSH SIGNATURE-----";

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum Error {
    #[error("empty namespace")]
    EmptyNamespace,
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHash(String),
    #[error("sign error: {0}")]
    SignError(String),
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Raw SSH signature: algorithm format string + raw signature blob.
pub struct SshSignature {
    pub format: String,
    pub blob: Vec<u8>,
}

/// SSH public key in wire format.
pub struct SshPublicKey {
    pub wire: Vec<u8>,
}

/// Trait for anything that can produce SSH signatures (e.g. an ssh-agent).
pub trait Signer {
    fn public_key(&self) -> &SshPublicKey;
    fn sign(&self, data: &[u8]) -> Result<SshSignature, Box<dyn std::error::Error + Send + Sync>>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write an SSH-string (4-byte big-endian length + payload) into `buf`.
fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Hash `message` with the given algorithm name, returning the digest bytes.
fn hash_message(hash_alg: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
    match hash_alg {
        HASH_SHA512 => {
            let mut hasher = Sha512::new();
            hasher.update(message);
            Ok(hasher.finalize().to_vec())
        }
        HASH_SHA256 => {
            let mut hasher = Sha256::new();
            hasher.update(message);
            Ok(hasher.finalize().to_vec())
        }
        other => Err(Error::UnsupportedHash(other.to_string())),
    }
}

/// Build the "signed data" blob that the signer will actually sign.
///
/// Layout (from the OpenSSH SSHSIG spec):
///   MAGIC_PREAMBLE (6 raw bytes, no length prefix)
///   SSH-string(namespace)
///   SSH-string(reserved = "")
///   SSH-string(hash_alg)
///   SSH-string(H(message))
fn build_signed_data(namespace: &str, hash_alg: &str, message_hash: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC_PREAMBLE);
    write_ssh_string(&mut buf, namespace.as_bytes());
    write_ssh_string(&mut buf, b""); // reserved
    write_ssh_string(&mut buf, hash_alg.as_bytes());
    write_ssh_string(&mut buf, message_hash);
    buf
}

/// Marshal the final SSHSIG envelope (binary, before armoring).
///
/// Layout:
///   MAGIC_PREAMBLE (6 raw bytes)
///   uint32(SIG_VERSION)      -- 4 bytes big-endian, NOT an SSH-string
///   SSH-string(pubkey_wire)
///   SSH-string(namespace)
///   SSH-string(reserved = "")
///   SSH-string(hash_alg)
///   SSH-string(sig_wire)
///
/// where sig_wire is:
///   SSH-string(format) + SSH-string(sig_blob)
fn marshal_signature(
    pubkey: &SshPublicKey,
    namespace: &str,
    hash_alg: &str,
    sig: &SshSignature,
) -> Vec<u8> {
    // Build sig_wire = SSH-string(format) + SSH-string(blob)
    let mut sig_wire = Vec::new();
    write_ssh_string(&mut sig_wire, sig.format.as_bytes());
    write_ssh_string(&mut sig_wire, &sig.blob);

    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC_PREAMBLE);
    buf.extend_from_slice(&SIG_VERSION.to_be_bytes());
    write_ssh_string(&mut buf, &pubkey.wire);
    write_ssh_string(&mut buf, namespace.as_bytes());
    write_ssh_string(&mut buf, b""); // reserved
    write_ssh_string(&mut buf, hash_alg.as_bytes());
    write_ssh_string(&mut buf, &sig_wire);
    buf
}

/// PEM-style armor: base64 with 70-column wrapping and BEGIN/END markers.
fn armor(data: &[u8]) -> Vec<u8> {
    let b64 = STANDARD.encode(data);
    let mut out = String::new();
    out.push_str(BEGIN_MARKER);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(ARMOR_LINE_LEN) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is always valid utf-8"));
        out.push('\n');
    }
    out.push_str(END_MARKER);
    out.push('\n');
    out.into_bytes()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Sign `message` under `namespace` using SHA-512 (the default hash).
pub fn sign(signer: &dyn Signer, namespace: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
    sign_with_hash(signer, namespace, HASH_SHA512, message)
}

/// Sign `message` under `namespace` using the specified hash algorithm.
pub fn sign_with_hash(
    signer: &dyn Signer,
    namespace: &str,
    hash_alg: &str,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    if namespace.is_empty() {
        return Err(Error::EmptyNamespace);
    }

    // 1. Hash the message.
    let message_hash = hash_message(hash_alg, message)?;

    // 2. Build the blob that the signer will sign.
    let signed_data = build_signed_data(namespace, hash_alg, &message_hash);

    // 3. Sign it.
    let sig = signer
        .sign(&signed_data)
        .map_err(|e| Error::SignError(e.to_string()))?;

    // 4. Marshal the full SSHSIG envelope.
    let envelope = marshal_signature(signer.public_key(), namespace, hash_alg, &sig);

    // 5. Armor and return.
    Ok(armor(&envelope))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Dummy signer for tests that don't need real cryptography.
    struct DummySigner {
        pubkey: SshPublicKey,
    }

    impl DummySigner {
        fn new() -> Self {
            Self {
                pubkey: SshPublicKey {
                    wire: vec![0u8; 32],
                },
            }
        }
    }

    impl Signer for DummySigner {
        fn public_key(&self) -> &SshPublicKey {
            &self.pubkey
        }
        fn sign(
            &self,
            _data: &[u8],
        ) -> Result<SshSignature, Box<dyn std::error::Error + Send + Sync>> {
            Ok(SshSignature {
                format: "ssh-ed25519".to_string(),
                blob: vec![0u8; 64],
            })
        }
    }

    #[test]
    fn test_armor_wrap_70() {
        let data = vec![0u8; 140];
        let armored = armor(&data);
        let text = std::str::from_utf8(&armored).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        // First line is BEGIN marker.
        assert_eq!(lines[0], BEGIN_MARKER);
        // Last line is END marker.
        assert_eq!(lines[lines.len() - 1], END_MARKER);

        // All base64 lines except possibly the last one must be exactly 70 chars.
        let b64_lines = &lines[1..lines.len() - 1];
        assert!(!b64_lines.is_empty(), "should have at least one base64 line");
        for line in &b64_lines[..b64_lines.len() - 1] {
            assert_eq!(
                line.len(),
                70,
                "interior base64 line should be 70 chars, got {}",
                line.len()
            );
        }
    }

    #[test]
    fn test_sign_rejects_empty_namespace() {
        let signer = DummySigner::new();
        let result = sign(&signer, "", b"hello");
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), Error::EmptyNamespace),
            "expected EmptyNamespace error"
        );
    }

    #[test]
    fn test_write_ssh_string() {
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, b"hello");
        assert_eq!(buf[0..4], [0, 0, 0, 5]);
        assert_eq!(&buf[4..], b"hello");
    }

    #[test]
    fn test_build_signed_blob_structure() {
        let hash = vec![0u8; 64]; // fake hash
        let blob = build_signed_data("git", HASH_SHA512, &hash);

        // Must start with raw SSHSIG magic (6 bytes, no length prefix).
        assert_eq!(&blob[..6], b"SSHSIG");

        // Next should be SSH-string("git") = [0,0,0,3] + b"git"
        assert_eq!(&blob[6..10], &[0, 0, 0, 3]);
        assert_eq!(&blob[10..13], b"git");
    }
}
