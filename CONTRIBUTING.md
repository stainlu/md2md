# Contributing

md2md is an early protocol proposal plus a reference Cloudflare Worker.

Good contributions are small, inspectable, and tied to the local-first contract:

- clarify the protocol
- improve the Worker implementation
- add publisher or subscriber examples
- harden the trust model
- improve validation for hosted markdown

## Development

```bash
npm run validate
cd worker
npm ci
npm run check
```

## Content Guidelines

Markdown in `mdwiki/` is served directly to agents. Keep it:

- complete enough to be useful offline
- explicit about source and sync behavior
- free of hidden instructions or invisible text
- easy to diff

Every top-level file in `mdwiki/` must include `md2md:` frontmatter with a canonical URL that matches the filename.

## Pull Requests

For protocol changes, include:

- the problem being solved
- the proposed frontmatter or sync behavior
- agent safety implications
- any compatibility impact for existing subscribers

For Worker changes, include the local check output.
