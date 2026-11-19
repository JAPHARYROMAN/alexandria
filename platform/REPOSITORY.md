# Run the Phase 2 repository

This milestone distributes a signed catalogue of the permitted seed records. A release carries a monotonically increasing number, a preceding digest, source credits, permissions and cumulative withdrawals. The publisher imports only the founding collection’s public projection. Importing the same data again preserves the release number. A withdrawn source stays withdrawn when the input is imported again.

## Start the processes

From `platform`, run these commands in a Unix shell with Go and OpenSSL 3. The working directory below holds test state. Each reader needs its own private storage directory. Supply a separately trusted signing public key when connecting a reader to a real operator.

```sh
work=$(mktemp -d)
go build -o "$work/alexandria-repo" ./cmd/alexandria-repo
openssl genpkey -algorithm Ed25519 -out "$work/publisher.pem"
openssl pkey -in "$work/publisher.pem" -pubout -out "$work/public.pem"
"$work/alexandria-repo" publish -store "$work/catalogue" -signing-key "$work/publisher.pem"
"$work/alexandria-repo" origin -store "$work/catalogue" -public-key "$work/public.pem" -listen 127.0.0.1:8600 &
"$work/alexandria-repo" node -store "$work/node-a" -public-key "$work/public.pem" -upstream http://127.0.0.1:8600/v1/head -listen 127.0.0.1:8601 &
"$work/alexandria-repo" node -store "$work/node-b" -public-key "$work/public.pem" -upstream http://127.0.0.1:8600/v1/head -listen 127.0.0.1:8602 &
curl -i http://127.0.0.1:8601/v1/records/moon-identity
```

Each record response includes a `Content-Location` header with its versioned path. Append `/lines/1` to that path on either reader for a citation to the first line. A link-only record has no citable body. A change to any public record field produces a new version identifier. This milestone serves citations only for the currently permitted version.

Publish a withdrawal while a reader is stopped. The surviving reader sees the change on its next request. Restart the other reader with its original storage directory and verify the same citation returns 410. The automated exercise starts and stops its own processes and uses a disposable key.

```sh
"$work/alexandria-repo" publish -store "$work/catalogue" -signing-key "$work/publisher.pem" -withdraw moon-identity
bash integration/two-nodes.sh
```

## Storage, trust and availability

Keep the signing key on the publishing machine. The origin and readers only need the public key. Each origin release is an immutable signed file. The origin exposes only the latest release. Older private archive files may contain previously permitted bodies and need restricted storage and a retention policy. Each reader atomically replaces its current on-disk checkpoint. One reader process owns each checkpoint directory.

A restarted node verifies its checkpoint and contacts the origin before answering a citation. A lower release number, conflicting release, missing withdrawal or invalid signature causes the request to fail closed. A new node trusts the operator’s live origin for its initial head. Remote origins require HTTPS. For a cross-host deployment, place the loopback listener behind an HTTPS reverse proxy and disable intermediary caching on these endpoints.

Two independent reader processes can survive the loss of one reader. They share a live origin dependency. Origin unavailability stops reads. This first implementation transfers the complete bounded catalogue on each read. Deployment in separate hosting environments, incremental changes, a dedicated object store and index rebuild, and operational backup/restore testing remain Phase 2 work.
