# Alexandria

Alexandria is an open-source global knowledge repository in development. The founder owns the official platform and decides its policy, releases, roadmap and node membership. Individual works carry their own credits and permissions.

## Phase 1 · Founding terms

The Go command validates the founding charter and seed collection, shows what the proposed official nodes may copy, and verifies an owner-signed decision. Its five internal test records cover two collections, **Reading the Sky** and the **General Reading Room**. They include a reusable Wikidata extract, two original sample texts and two external links. The original sample texts can be distributed with this source code as test fixtures. Their catalogue settings simulate the handling of private submissions.

The candidate software licence is Apache-2.0. The proposed first source is the English label and description of the Moon from Wikidata item Q405. Its specific revision, credit and CC0 evidence are in the manifest. The owner’s approval of this packet is pending. Approval of Phase 1 authorizes the next engineering phase. The public platform release has a later decision.

## Run locally

From the project directory, use Go 1.25 or newer. The command uses only the Go standard library.

```sh
cd platform
go test ./...
go vet ./...
go build -o alexandria ./cmd/alexandria
go run ./cmd/alexandria check
go run ./cmd/alexandria shelf -collection reading-the-sky
go run ./cmd/alexandria replication-plan
```

On Windows, use `go build -o alexandria.exe ./cmd/alexandria` for a named executable. Commands default to the `founding` directory. Pass `-dir` to use another proposal. The shelf and review packet contain internal material. The replication plan emits an eligible public projection and never sends data over the network.

## Review and approve

1. Review [the charter](platform/founding/charter.md) and [the manifest](platform/founding/manifest.json). Check the collection scopes, proposed software licence, reserved release authority and first source. Provide changes before signing.
2. From `platform`, export a packet to a fresh path in a private directory. The destination filesystem must support hard links. Existing files are preserved.
3. The owner reads the exported packet and signs those exact bytes using their own Ed25519 key. Keep the private key outside this repository and under the owner's control.
4. Verify the current proposal using the detached signature and the owner's independently authenticated public key. An independent operator should obtain and pin the public key through an established owner-controlled channel. A key supplied with a proposal cannot establish the owner's identity.
5. Keep the signature, exact packet, and trusted public-key fingerprint with the dated decision record. A changed proposal requires a new signature.

Example for a workstation where OpenSSL 3 and the owner's existing key are available. In these commands `../owner-review` is an existing private directory outside the platform module, and the PEM public key uses SubjectPublicKeyInfo format. Use a fresh output filename for a second review.

```sh
go run ./cmd/alexandria review -out ../owner-review/founding.txt
openssl pkeyutl -sign -rawin -inkey ../owner-review/owner-private.pem -in ../owner-review/founding.txt -out ../owner-review/founding.sig
go run ./cmd/alexandria verify -owner-key ../owner-review/trusted-owner-public.pem -signature ../owner-review/founding.sig
```

Validation and verification return a nonzero exit code on failure. Verification rebuilds the packet from the current charter and manifest. Manifest indentation and Windows line endings in the charter can change without altering the decision. Substantive changes to the licence, terms, credits, permissions or record contents invalidate the signature.

## Contributing

Propose a focused change with its tests and permission evidence for any new source. Add real private submissions and owner signing material only to a separate protected workspace. The repository fixtures are intentionally safe to publish. Changes to official terms go back to the owner for approval. The charter describes how reviews and proposals in the future in-app Community Forum will guide releases.

The project’s [founding paper](ALEXANDRIA_White_Paper.pdf) and [development roadmap](ALEXANDRIA_Development_Roadmap.docx) define the subsequent phases.
