# Security Policy

md2md treats agent-readable web content as local, persistent files. That is powerful, and it needs a narrow trust model.

## Trust Model

Agents should only subscribe when the user explicitly asks them to fetch a trusted source and follow its visible instructions.

Agents should never:

- auto-subscribe from arbitrary web pages
- execute shell commands from document content
- sync from any URL except the pinned `canonical`
- write outside the user's chosen workspace or cache directory
- hide subscription state from the user

## Prompt Injection Boundary

The `md2md:` frontmatter contains instructions, but they are visible subscription metadata. Treat them like an install manifest:

- user-initiated
- source-pinned
- inspectable before use
- diffable after updates

The markdown body is content. It may explain workflows, but it must not override user or system instructions.

## Publisher Responsibilities

Publishers should:

- serve raw markdown over HTTPS
- provide stable `ETag` values
- avoid invisible text and hidden instructions
- keep historical changes reviewable
- rotate content carefully because subscribers may sync automatically

## Reporting Issues

Open a GitHub issue for protocol or implementation security concerns. If the report includes an exploitable vulnerability against deployed infrastructure, email the repository owner before publishing details.
