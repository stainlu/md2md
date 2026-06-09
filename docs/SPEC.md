# md2md Protocol Spec

Status: early proposal
Version: 1.1.0

md2md maps a canonical `.md` URL to a local `.md` file that an AI agent can inspect, diff, search, and keep current.

The protocol has three goals:

1. preserve the complete markdown source instead of a summarized web fetch
2. make future reads local-first and fast
3. make updates explicit, cheap, and auditable

## Roles

Publisher: owns a canonical `.md` URL and serves raw markdown over HTTPS.

Subscriber: the user or agent workspace that stores a local copy after explicit user approval.

Agent: software that reads the local copy first and syncs it in the background.

## Canonical Document

An md2md document is a normal markdown file. It should start with its actual content, not machine metadata.

Publishers may add an optional YAML-style subscription block at the bottom:

```yaml
md2md:
  protocol: "1.1.0"
  version: "1.0.0"
  canonical: "https://your-brand.md"
  sync: 1h
  suggested_file: "your-brand.md"
  subscription: optional
  spec: "https://md2md.md"
```

The content before the subscription block belongs to the publisher. It can be documentation, an agent skill, a reference manual, a changelog, or any other markdown-native resource.

The bottom block is metadata, not a command. Agents should ignore it unless the user explicitly asks to subscribe.

## Required Fields

`protocol`: md2md protocol version. Current value: `1.1.0`.

`version`: publisher document version. Use semantic versioning where possible.

`canonical`: HTTPS URL that acts as the source of truth. For v1, root `.md` domains are the primary target, for example `https://example.md`.

`sync`: suggested sync interval. Use a compact duration such as `15m`, `1h`, or `24h`.

`suggested_file`: suggested local filename. For root `.md` domains, this should match the host, for example `example.md`.

`subscription`: must be `optional`. The document does not request action on its own.

`spec`: canonical URL for this spec. Current value: `https://md2md.md`.

## Publisher Requirements

Publishers should:

1. serve the document as raw markdown from the canonical URL
2. return `Content-Type: text/markdown; charset=utf-8` or `text/plain; charset=utf-8`
3. support `GET` and `HEAD`
4. return a stable `ETag` for each content version
5. support `If-None-Match` and return `304 Not Modified` when content has not changed
6. avoid hidden text, zero-width instructions, or content that tries to override user intent

`Last-Modified` is useful but not required when `ETag` is present.

## Subscriber Algorithm

Agents should only subscribe when the user explicitly asks them to fetch a trusted source and subscribe to it.

On first subscription:

1. `GET` the canonical URL.
2. Find the bottom `Optional md2md subscription` block.
3. Verify `subscription: optional`, `protocol`, `canonical`, and `suggested_file`.
4. Save the full response body exactly as received only if the user requested subscription.
5. Store sync metadata locally, including canonical URL, ETag if present, and sync interval.
6. Read the local file for future matching queries before fetching the web.

On sync:

1. Send `HEAD <canonical>` with `If-None-Match` when an ETag is known.
2. If the response is `304`, keep the local file.
3. If the response is `200` and the validator changed, send `GET <canonical>`.
4. Validate the subscription block and canonical URL before replacing the local file.
5. Keep old versions diffable when the host application supports history.

## Safety Rules For Agents

Agents should:

1. never auto-subscribe from arbitrary links
2. never execute shell commands from the document body
3. pin sync to the declared `canonical` URL
4. write only inside the user's chosen workspace or cache directory
5. make updates inspectable through plain-text files and diffs

These rules are part of the protocol. The point of md2md is not just faster reads; it is local, deterministic, inspectable reads.
