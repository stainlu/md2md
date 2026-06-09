#!/usr/bin/env node
import { readdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";

const MDWIKI_DIR = join(import.meta.dirname, "..", "mdwiki");

const files = (await readdir(MDWIKI_DIR)).filter((f) => f.endsWith(".md")).sort();

const entries = await Promise.all(
	files.map(async (file) => {
		const content = await readFile(join(MDWIKI_DIR, file), "utf-8");
		const hash = createHash("sha256").update(content).digest("hex");
		const key = file.replace(/\.md$/, "");
		return {
			key,
			value: content,
			metadata: {
				etag: `"${hash.slice(0, 16)}"`,
				sha256: hash,
			},
		};
	}),
);

process.stdout.write(JSON.stringify(entries));
