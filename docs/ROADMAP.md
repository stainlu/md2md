# Roadmap

md2md is intentionally small. The next work should make the local-first contract easier for agents and publishers to implement without turning the protocol into a platform.

## Near Term

- finalize the v1.1 bottom subscription block fields
- publish reference subscriber behavior for common agent environments
- add a tiny sync helper that stores canonical URL, ETag, and local path metadata
- add examples for one-page docs, agent skills, and long-form knowledge bases
- document recommended cache locations for different agent tools

## Protocol Questions

- Should v1 require root `.md` domains only, or allow path-based canonical URLs?
- Should publishers include an optional `sha256` field in the subscription block, or is HTTP `ETag` enough?
- Should local metadata live beside the file, under `.md2md/`, or be left to each agent host?
- How should agents resolve naming collisions such as `brand.md` from multiple sources?
- What is the right unsubscribe and tombstone behavior?

## Local Internet Direction

The larger experiment is a local internet for agents:

- canonical web resources remain addressable by URL
- subscribed resources become local files
- agent search starts locally
- updates happen asynchronously
- users can inspect, diff, pin, or delete what their agent knows

md2md starts with `.md` domains because markdown is already the agent-native document format and the domain maps cleanly to the local filename.
