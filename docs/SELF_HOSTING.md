# Self-Hosting md2md

This repo includes a Cloudflare Worker that maps `.md` hostnames to markdown stored in Cloudflare KV.

Request flow:

```text
https://soc2.md
  -> Worker receives host soc2.md
  -> Worker derives KV key soc2
  -> Worker returns mdwiki/soc2.md content
```

## Prerequisites

- Node.js 20+
- Cloudflare account
- Wrangler authenticated locally or in CI
- A Cloudflare KV namespace
- One custom domain route per `.md` domain

## Add A Domain

1. Add a markdown file under `mdwiki/`.

   Example: `mdwiki/example.md` will be served from `https://example.md`.

2. Add an optional md2md subscription block at the bottom with a matching canonical URL.

3. Add a route in `worker/wrangler.toml`:

```toml
[[routes]]
pattern = "example.md"
custom_domain = true
```

4. Validate the content:

```bash
npm run validate
```

5. Generate the KV bulk payload:

```bash
npm run --silent kv:bulk > /tmp/md2md-kv.json
```

6. Upload to KV:

```bash
npm --prefix worker exec wrangler -- kv bulk put /tmp/md2md-kv.json \
  --namespace-id <KV_NAMESPACE_ID> --remote
```

7. Deploy the Worker:

```bash
cd worker
npm ci
npm run deploy
```

## Local Worker Check

Run the Worker build check without deploying:

```bash
cd worker
npm ci
npm run check
```

## HTTP Behavior

The Worker should:

- return raw markdown for `GET`
- return headers only for `HEAD`
- include `ETag`
- honor `If-None-Match`
- return `304 Not Modified` when the local agent already has the current version
- return `405 Method Not Allowed` for unsupported methods

These details matter because md2md sync should be cheap enough to run in the background.
