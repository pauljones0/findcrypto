# Wallet-specific browser artifacts

FindCrypto names a wallet only when the surrounding evidence proves the
attribution. An encryption envelope alone is not enough: installed extension
source bundles contain the same schema strings as live storage, and several
wallets use generic key names.

This note records the current, version-scoped evidence reviewed on 2026-11-24.
It is an implementation plan, not a claim that private extension storage is a
permanent public API.

## Required storage context

For Chromium-family profiles, parse records under:

    <profile>/Local Extension Settings/<extension-id>/

Do not brand matches found under:

    <profile>/Extensions/<extension-id>/<version>/

The latter is installed program code and will self-trigger on field names and
schema literals. Firefox requires resolving an add-on's internal origin/UUID
from profile metadata and then reading its `storage.local`; one fixed path is
not portable.

## Versioned adapter evidence

| Wallet | Package identity reviewed | Coherent live-storage evidence |
|---|---|---|
| Phantom 26.43.0 | Chrome `bfnaelmomeimhlpmgjnjophhpkkoljpa` | `.phantom-labs.encryption.encryptionKey`; version 1 `encryptedKey` with scrypt, base58 salt/nonce/ciphertext, iterations 10000 and SHA-256. Validate decoded 16-byte salt, 24-byte nonce, and 48-byte ciphertext. Current scrypt parameters are N=4096, r=8, p=1, dkLen=32; retain separately tested legacy PBKDF2 support. |
| Solflare 2.44.2 | Chrome `bhhhlbepdkbapadjdnnojkbgioiodbic` | `walletdata` plus the extension namespace; `locked:true` and PBKDF2 data with base64 ciphertext/nonce/salt, iterations 600000, SHA-256, and base64 encoding. Validate 16-byte salt and 24-byte nonce. Legacy `solflaredata` is stronger attribution evidence; legacy values use base58. |
| Keplr 0.13.53 Chrome / 0.13.49 Firefox | Chrome `dmkamcknogkgcdfhhbddcghachkejeap`; Firefox `keplr-extension@keplr.app` | Aggregate one database's `vault/userPasswordSalt`, `vault/aesCounterSalt`, `vault/passwordCipher`, `vault/userPasswordMac`, `vault/aesCounterCipher`, and validated `vault/vaultMap`; a single fragment is insufficient. Legacy `keyring/key-multi-store` version 1.2 is a distinct AES-128-CTR/scrypt keystore (N=131072, r=8, p=1, dkLen=32), not ERC-2335. |

Reproducibility hashes of the inspected signed packages:

    Phantom 26.43.0   ead7273e79a57dc9e653e9a268c1b7ce2eb9efb3f3ad073909465c1125493a42
    Solflare 2.44.2  e74259bbc6bbd97e0d7cd626f6a6cee87f1514bea7c6e13eee18e401b8a433cc
    Keplr 0.13.53     f8668c23905842aecf2a0b199beffa5dcc27bd8c63c8131471eef0a293c156f5
    Keplr FF 0.13.49  eceb329ce94b8c394363db6d8f3ef2951bedc89b1bee3261ff42eda1affc5c4f

## Admission tests

A wallet adapter is ready only when it has:

1. a WebExtension/LevelDB storage reader that preserves database and extension
   namespace context;
2. strict version, KDF, encoding, decoded-length, and coherent-record checks;
3. fixtures derived reproducibly from the reviewed signed package;
4. negative tests for the same record under the wrong extension ID, detached
   fragments, corrupt lengths, and matching strings inside extension source;
5. a generic/unknown result for unrecognized future schema revisions.

Until then, a valid shared `{data, iv, salt}` envelope remains
`browser-passworder-vault`. It must not be relabeled MetaMask, Phantom,
Solflare, or Keplr. Phantom's public `indexed-db-stamper` package stores SDK
authentication keys, not the extension recovery vault, and is out of scope.

Primary references:

- [Chromium extension constants](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/extensions/common/constants.h)
- [Chrome storage API](https://developer.chrome.com/docs/extensions/reference/api/storage)
- [Phantom download](https://phantom.com/download)
- [Solflare download](https://www.solflare.com/download/)
- [Keplr download](https://www.keplr.app/get)
- [Keplr Firefox listing](https://addons.mozilla.org/en-US/firefox/addon/keplr/)
- [Phantom indexed-db-stamper scope](https://github.com/phantom/phantom-connect-sdk/blob/main/packages/indexed-db-stamper/README.md)
