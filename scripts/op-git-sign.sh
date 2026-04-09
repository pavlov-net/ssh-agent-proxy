#!/usr/bin/env bash
#
# op-git-sign: a drop-in replacement for ssh-keygen when used as
# `gpg.ssh.program` inside a container. For "-Y sign" operations it forwards
# the data to sign to op-sign-proxy running on the host (by default at
# http://127.0.0.1:7221/sign) and returns the armored SSHSIG signature that
# ssh-keygen would have produced. For any other ssh-keygen sub-command
# (notably "-Y check-novalidate" / "-Y verify") it transparently execs the
# real ssh-keygen, so signature verification continues to work as long as
# openssh-client is installed in the container.
#
# Git invokes gpg.ssh.program roughly as:
#
#     <program> -Y sign -n git -f <signing-key> [file|-]
#
# where the data to sign is piped on stdin and the signature is read back
# from stdout. If a file argument is given, ssh-keygen writes the signature
# to "<file>.sig" instead; we preserve that behaviour.
#
# Public-key bootstrap: the proxy exposes GET /publickey returning the
# OpenSSH-format public key line for the key it loaded from 1Password. When
# git passes a `-f <path>` that doesn't exist yet, this shim fetches that
# key and writes it to <path> before signing. That means the container's
# `user.signingkey` can point to e.g. ~/.cache/op-git-sign/signing.pub and
# the file will be created on first use — no specific public key needs to
# be baked into the container image or dotfiles. `rm` the cache file to
# force a refresh after rotating the key in 1Password.
#
# Subcommands:
#
#     op-git-sign pubkey [path]
#         Fetch the public key from the proxy and print it to stdout, or
#         write it to <path> if given. Useful for bootstrapping
#         allowedSignersFile or seeding dotfiles.
#
# Environment variables:
#
#   OP_SIGN_PROXY_URL         Full URL of the sign endpoint
#                             (default: http://127.0.0.1:7221/sign)
#   OP_SIGN_PROXY_PUBKEY_URL  Full URL of the publickey endpoint
#                             (default: derived from OP_SIGN_PROXY_URL by
#                             replacing /sign with /publickey)
#   OP_SIGN_PROXY_CURL        Override the curl binary (default: curl)
#
# Usage inside the container:
#
#   git config --global gpg.format ssh
#   git config --global gpg.ssh.program /usr/local/bin/op-git-sign
#   git config --global user.signingkey ~/.cache/op-git-sign/signing.pub
#   git config --global commit.gpgsign true
#   git config --global tag.gpgsign true

set -euo pipefail

PROXY_URL="${OP_SIGN_PROXY_URL:-http://127.0.0.1:7221/sign}"
PUBKEY_URL="${OP_SIGN_PROXY_PUBKEY_URL:-${PROXY_URL%/sign}/publickey}"
CURL="${OP_SIGN_PROXY_CURL:-curl}"

die() {
    printf 'op-git-sign: %s\n' "$*" >&2
    exit 1
}

fetch_pubkey() {
    "$CURL" --silent --show-error --fail "$PUBKEY_URL"
}

# Handle the `pubkey` subcommand before any argument parsing. Everything
# else is assumed to be an ssh-keygen-compatible invocation from git.
if [[ $# -ge 1 && "$1" == "pubkey" ]]; then
    if [[ $# -eq 1 ]]; then
        fetch_pubkey
    elif [[ $# -eq 2 ]]; then
        dest="$2"
        mkdir -p "$(dirname "$dest")"
        tmp="$(mktemp "${dest}.XXXXXX")"
        trap 'rm -f "$tmp"' EXIT
        fetch_pubkey >"$tmp"
        mv "$tmp" "$dest"
        trap - EXIT
    else
        die "usage: op-git-sign pubkey [path]"
    fi
    exit 0
fi

# First pass: figure out whether this is a "-Y sign" invocation. Everything
# else gets delegated to real ssh-keygen verbatim.
mode=""
for ((i = 1; i <= $#; i++)); do
    if [[ "${!i}" == "-Y" ]]; then
        next=$((i + 1))
        if (( next <= $# )); then
            mode="${!next}"
        fi
        break
    fi
done

if [[ "$mode" != "sign" ]]; then
    if ! command -v ssh-keygen >/dev/null 2>&1; then
        die "operation '-Y ${mode:-?}' requires ssh-keygen, which is not installed"
    fi
    exec ssh-keygen "$@"
fi

# Second pass: parse the sign-specific arguments we care about. We keep this
# intentionally narrow — just enough to mirror how git drives ssh-keygen.
namespace=""
keyfile=""
files=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -Y)
            # Already consumed above, skip value.
            shift 2
            ;;
        -n)
            namespace="$2"
            shift 2
            ;;
        -f)
            keyfile="$2"
            shift 2
            ;;
        -O)
            # Pass-through ssh-keygen options; we don't forward them because
            # the proxy does not implement them, but we silently accept so
            # that git's defaults don't blow up.
            shift 2
            ;;
        -q|-v|-U)
            shift
            ;;
        --)
            shift
            while [[ $# -gt 0 ]]; do
                files+=("$1")
                shift
            done
            ;;
        -*)
            die "unsupported flag: $1"
            ;;
        *)
            files+=("$1")
            shift
            ;;
    esac
done

namespace="${namespace:-git}"
if [[ "$namespace" != "git" ]]; then
    die "proxy is hardcoded to namespace 'git' (got '$namespace')"
fi

# Auto-populate the signing-key file if git handed us a path that doesn't
# exist yet. Git writes literal `user.signingkey` values to a temp file
# (which *does* exist, so we leave it alone), but when `user.signingkey` is
# an absolute path to an empty location we use that as a cache for the
# public key fetched from the proxy. This is the "no specific pubkey baked
# into the container" path documented in the README.
if [[ -n "$keyfile" && ! -e "$keyfile" ]]; then
    mkdir -p "$(dirname "$keyfile")"
    tmp="$(mktemp "${keyfile}.XXXXXX")"
    if fetch_pubkey >"$tmp"; then
        mv "$tmp" "$keyfile"
    else
        rm -f "$tmp"
        die "failed to fetch public key from $PUBKEY_URL"
    fi
fi

post_sign() {
    # --fail makes curl exit non-zero on HTTP errors; --data-binary @-
    # streams stdin without any newline mangling.
    "$CURL" --silent --show-error --fail \
        --header 'Content-Type: application/octet-stream' \
        --data-binary @- \
        "$PROXY_URL"
}

if [[ ${#files[@]} -eq 0 || "${files[0]}" == "-" ]]; then
    # Sign stdin → stdout, matching git's expectation.
    post_sign
else
    # ssh-keygen writes to "<file>.sig" when given a real file argument.
    target="${files[0]}"
    [[ -r "$target" ]] || die "cannot read $target"
    post_sign <"$target" >"${target}.sig"
fi
