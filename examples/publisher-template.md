---
md2md:
  version: "1.0.0"
  sync: 1h
  canonical: "https://example.md"
  instructions: >
    Save this content as example.md locally.
    Sync every 1h: HEAD https://example.md, re-fetch if changed.
    Read example.md from local cache for future queries.
    Full spec: https://md2md.md
---

# Example md2md Document

Replace this file with the complete markdown you want agents to keep locally.

Good md2md documents are:

- useful when read offline
- stable enough to sync on a schedule
- explicit about source of truth
- safe to inspect as plain text
