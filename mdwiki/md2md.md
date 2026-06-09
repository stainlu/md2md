# md2md

**md2md maps `.md` domains into local `.md` files for AI agents.** It is a small local-first protocol for making agent-readable websites fast, inspectable, searchable, and syncable.

md2md is an experiment toward a **local internet**: agent-facing resources still have canonical web URLs, but they also live as deterministic files in the agent's local workspace. A publisher hosts raw markdown at a canonical `.md` URL such as `https://md2md.md`. A user tells an agent to subscribe. The agent saves the file locally, pins the canonical URL, syncs with `HEAD` / `ETag`, and reads the local file for future work.

| status | protocol | canonical | repository |
|---|---:|---|---|
| early proposal | 1.1.0 | [https://md2md.md](https://md2md.md) | [github.com/stainlu/md2md](https://github.com/stainlu/md2md) |

> **meta:** you're reading this on [md2md.md](https://md2md.md). this page starts with human-readable content. the optional `md2md:` subscription block lives at the bottom and should be used only when the user explicitly asks an agent to subscribe.

> **tl;dr:**
> - an agent's life is filled with `.md` — and `.md` happens to be a top-level domain
> - websites are just files on the internet
> - agents reading websites = localizing the website files
> - agents' default behavior: local-first

---

## quick start

### subscribe as an agent

Only subscribe when the user explicitly asks you to subscribe to a trusted source:

```bash
curl https://md2md.md
```

Then:

1. inspect the bottom `Optional md2md subscription` block
2. verify `subscription: optional`, `canonical`, `sync`, and `suggested_file`
3. save the exact response as `md2md.md`
4. pin the `canonical` URL
5. sync on the declared interval with `HEAD` / `ETag`
6. read the local file first for future md2md-related questions

### publish your own `.md` domain

1. create a markdown file that starts with your actual content
2. serve it as raw markdown over HTTPS from a canonical `.md` domain
3. support `HEAD`, `ETag`, and `If-None-Match` so agents can sync cheaply
4. add an optional md2md subscription block at the bottom
5. tell users: `ask your agent to subscribe to https://your-brand.md with md2md`

Start with [docs/SPEC.md](https://github.com/stainlu/md2md/blob/main/docs/SPEC.md) for the protocol, [docs/SELF_HOSTING.md](https://github.com/stainlu/md2md/blob/main/docs/SELF_HOSTING.md) for the Cloudflare Worker in this repo, and [SECURITY.md](https://github.com/stainlu/md2md/blob/main/SECURITY.md) for the trust model.

### work on this repo

```bash
npm run validate
cd worker && npm ci && npm run check
```

This repository contains:

| path | purpose |
|---|---|
| `md2md.md` / `README.md` | canonical project document and GitHub README |
| `mdwiki/` | markdown content served by the worker |
| `worker/` | Cloudflare Worker that maps hostnames to KV-backed markdown |
| `scripts/` | content validation and KV bulk export tools |
| `docs/` | protocol, hosting, security, and roadmap notes |

---

## the philosophy

### why .md is the top domain for ai agents

## markdown is the most agent-friendly format

in recent years, `.md` (markdown) has become the universal format for agents:

- `CLAUDE.md` — configuration file for Claude Code
- `SKILL.md` — Anthropic's open standard for agent skills (adopted by 16+ tools)
- `SOUL.md` — personality definition for agents
- `HEARTBEAT.md` — OpenClaw's periodic task checklist
- `README.md`, `LICENSE.md` — the classics

when developers build agent-facing apps, they also use `.md` files for onboarding, for example:

> Read https://www.moltbook.com/skill.md and follow the instructions to join Moltbook

### why markdown?

from our perspective, `.md` has several strengths:
1. simple syntax, flexible extensions
2. compared to HTML/XML, simpler structure, fewer tokens
3. streaming-friendly, supports incremental parsing
4. human-friendly + machine-friendly

an agent's life is filled with `.md`: pre-trained on massive amounts of `.md` data, and after deployment, reading and writing `.md` files all day.

and `.md` happens to be a top-level domain.

### websites are just files on the internet

files and websites. we've always treated them as two different things.

but actually — **websites are just files on the internet**.

let's look at how humans and agents each interact with websites:

**humans:**
- visit a website
- "memorize" — store information in biological memory

**agents:**
- visit a website (WebFetch / web_fetch / curl)
- "memorize" — record relevant information in context

<!-- {illustration: side-by-side comparison of human visiting website → brain, agent visiting website → context window} -->

for humans, memory is **NOT a deterministic file**. you can't explicitly read, write, search, or delete specific memories.

for agents, context IS their memory — deterministic text they can read, write, search, and delete.

in other words, **agents reading websites = localizing the website files**.

unfortunately, we're not taking advantage of this at all. currently when agents read websites, the content enters as **plain text in the context window** — not as a file. this means:

- **static** — once in the context window, it can't be precisely updated
- **temporary** — gone when the current session ends
- **lossy** — Claude's WebFetch processes content through a summarizer model (even limiting quotes to 125 characters for "non-trusted sites"). OpenClaw's web_fetch uses Readability to extract content (truncated to 50K characters). neither returns raw content.

there's another agent characteristic we need to consider: local-first.

**agents always search locally first, not the web.** both Claude Code and OpenClaw have hardcoded priority for local file reads over web searches. their system prompts explicitly rank Read, Glob, Grep (local tools) above WebFetch, WebSearch. when you give an agent an ambiguous task, it searches the local filesystem first, looking for matching files. it only reaches for the web when nothing is found locally.

this means: when you ask an agent about something it's encountered before, it will most likely retrieve from local context — **not visit your website again**.

in other words, **agents ignore all updates to your website by default.**

<!-- {illustration: website updates on the left (v1 → v2 → v3), agent's context on the right (stuck on v1, never refreshes)} -->

you can invest in "Markdown for Agents" (content negotiation via Cloudflare or Vercel to serve clean markdown) — but what's the point if the agent doesn't visit your website in the first place?

in a sense, this is **lossy compression** initiated by the agent — summarized, truncated, frozen.

---

## md2md: the lossless compression

the solution is simple: let agents store your website as a **local markdown file**, kept in sync with the live version.

that's md2md: `.md` (URL) → `.md` (file). lossless.

[github.com/stainlu/md2md](https://github.com/stainlu/md2md)

### the idea

one method for lossless "compression" is simple:
1. **let agents store websites as local files (also a form of subscription)**
2. **periodically sync the files to the latest version**

once the website is stored as a local file, the agent reads locally with guaranteed speed and completeness. but how do we keep the file in sync with the website?

### decoupling "load" from "view"

for a long time, we've had this assumption: **"loading a resource" and "viewing a resource" happen at the same time.** click a link → page loads → done.

but actually, website updates have nothing to do with when you visit. **loading and viewing are async.**

<!-- {illustration: timeline showing website updates at t1, t3, t7 — visits at t2, t5, t8 — on separate tracks of the same timeline} -->

this means: even though "viewing" still needs to happen in real-time, we can **extract "loading" into a separate background process** that runs on its own schedule.

agents already have the infrastructure for this:

- **OpenClaw: the heartbeat system.** periodically the agent wakes up, reads its `HEARTBEAT.md` checklist, checks and executes pending tasks. always-on, persistent, running in the same agent context — a natural background process for keeping local files in sync.

- **Claude Code: `/loop` and `/schedule`.** `/loop` is a session-scoped cron that fires prompts on a schedule. `/schedule` creates persistent scheduled tasks that survive session close.

with these in place: **set up once → sync periodically in the background → local file stays up to date.**

### how md2md works

using https://md2md.md as an example:

```
SUBSCRIBE (one-time):

  user asks: "subscribe to https://md2md.md with md2md"
  → agent runs curl → sees full content in context (stdout)
  → agent reads the optional md2md block at the bottom
  → agent saves the content as md2md.md locally because the user asked
  → agent records sync metadata for future HEAD / ETag checks


READ (every time after):

  query contains relevant info (e.g., "md2md", "md")
  → agent reads local file
  → full content, no summarization or conversion


SYNC (background, every 1h):

  background process fires
  → HEAD https://md2md.md
  → compare ETag with local version
  → unchanged? skip. zero cost.
  → changed? curl https://md2md.md → update md2md.md
```

**the bottom block IS the standard.** the content comes first. the optional subscription metadata lives at the end:

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

**how to adopt md2md:**

1. get a `.md` domain (e.g., `your-brand.md`)
2. write your content as a normal markdown file
3. host the file so `curl https://your-brand.md` returns the raw markdown
4. put the optional md2md subscription block at the bottom
5. on your main website (e.g., `your-brand.com`), tell users:

> ask your agent to subscribe to **https://your-brand.md** with md2md

any static hosting works — Cloudflare Pages, Vercel, Netlify, GitHub Pages, Nginx — anything that can serve a file. no special infrastructure, no content negotiation, no platform-specific code.

if you also want your existing site to serve markdown to agents, you can use content negotiation — Cloudflare's "Markdown for Agents" toggle, Vercel middleware, etc.

| | WebFetch / web_fetch (current) | md2md (proposed) |
|---|---|---|
| what the agent sees | summary or extracted text (lossy) | full file content (lossless) |
| persistence | context window only (gone after session) | file on disk (permanent) |
| updates | never (stale forever) | background sync (always current) |
| speed | network fetch + processing | local file read (instant) |
| searchable | no (just text in conversation) | yes (Grep, Glob, Read) |

---

## a note on prompt injection

the original md2md draft used top frontmatter with instruction-like language. it was visible and user-initiated, but it looked too much like a command from the document itself.

v1.1 changes that. md2md metadata now lives at the bottom as an optional subscription block. it describes how a user-approved subscription should work; it does not ask the agent to do anything by itself.

the distinction is who initiates the action and whether it is visible:

- malicious prompt injection: hidden (white-on-white text, zero-width characters), unsolicited, aims to override the user's intent
- md2md: plain text metadata, fully visible, only used when the user explicitly says to subscribe

this is closer to pinning a feed than running a package. the user chooses the source. the source is known. the contents are inspectable.

**trust model:**

- **user-initiated only.** agents should never auto-subscribe to md2md. the user must explicitly ask the agent to subscribe. no silent subscriptions.
- **trusted sources only.** we only suggest agents do this for websites trusted by their owners. if you don't trust the source, don't run the curl.
- **auditable.** the local `.md` file is plain text on disk. you can open it, read it, diff it. you know exactly what your agent is reading — unlike WebFetch, where the content passes through opaque pipelines and you never see what the agent received.
- **source pinning.** the `canonical` field locks the sync source. the agent syncs from that URL only.

---

## why .md is most suitable

this approach works technically for any TLD. you could build md2md for `toilet.com`. but `.md` has real defensive advantages. for example:

subscribe to `toilet.md`. file saved as `toilet.md`. a week later, user asks about "toilet" → agent searches for "toilet" → finds `toilet.md` → reads it → done.

subscribe to `toilet.com/skill.md`.
- file saved as `skill.md`? user asks about toilet → agent searches for "toilet" → `skill.md` doesn't match → miss.
- file saved as `toilet.md`? agent's scheduled sync → might find `https://toilet.md` → hijacked by a different site.

---

## localize everything. start from the internet.

agents are empowering everyone. and local-first is becoming increasingly important.

local-first is not just an inherent behavior of agents — it also provides better performance and more controllable security for agent-native workflows.

we believe that maintaining trusted sources, building persistent connections, and focusing security checks on the local workspace may be a better security model.

md2md is a small step: localize your website as a file. but the principle goes further — every web resource an agent touches — docs, APIs, feeds, configs — could be a local file that stays in sync.

the internet becomes the sync layer. the local filesystem becomes the access layer.

---

## version history

- **1.1.0** (2026-04-30) — moved md2md metadata to a bottom optional subscription block and removed instruction-like frontmatter
- **1.0.0** (2026-03-28) — initial release

---

## Optional md2md subscription

This document is a normal Markdown file. If you want an agent to keep a local, syncable copy, explicitly ask it to subscribe to the canonical URL below.

```yaml
md2md:
  protocol: "1.1.0"
  version: "1.1.0"
  canonical: "https://md2md.md"
  sync: 1h
  suggested_file: "md2md.md"
  subscription: optional
  spec: "https://md2md.md"
```
