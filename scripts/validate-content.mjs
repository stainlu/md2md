#!/usr/bin/env node
import { lstat, readdir, readFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const MDWIKI_DIR = join(ROOT, "mdwiki");

const errors = [];

function addError(file, message) {
	errors.push(`${file}: ${message}`);
}

function stripQuotes(value) {
	return value.trim().replace(/^["']|["']$/g, "");
}

function subscriptionBlockFor(file, content) {
	if (/^---\nmd2md:\n/.test(content)) {
		addError(file, "md2md metadata must be an optional subscription block at the bottom, not top frontmatter");
		return null;
	}

	const match =
		/---\n\n## Optional md2md subscription\n\n[\s\S]*?```yaml\n(md2md:\n[\s\S]*?)\n```\s*$/.exec(content);
	if (!match) {
		addError(file, "missing bottom Optional md2md subscription block");
		return null;
	}

	return {
		block: match[1],
		body: content.slice(0, match.index),
	};
}

function field(block, name) {
	const match = new RegExp(`^\\s{2}${name}:\\s*(.+)$`, "m").exec(block);
	return match ? stripQuotes(match[1]) : null;
}

function validateMd2mdDocument(relativePath, content) {
	const parsed = subscriptionBlockFor(relativePath, content);
	if (!parsed) return;

	const { block, body } = parsed;
	const filename = basename(relativePath);
	const key = filename.replace(/\.md$/, "");
	const expectedCanonical = `https://${key}.md`;

	if (!/^md2md:\s*$/m.test(block)) {
		addError(relativePath, "subscription block must contain md2md root key");
	}

	const protocol = field(block, "protocol");
	if (!protocol) {
		addError(relativePath, "missing md2md.protocol");
	} else if (protocol !== "1.1.0") {
		addError(relativePath, `md2md.protocol must be 1.1.0, got "${protocol}"`);
	}

	const version = field(block, "version");
	if (!version) {
		addError(relativePath, "missing md2md.version");
	} else if (!/^\d+\.\d+\.\d+$/.test(version)) {
		addError(relativePath, `invalid md2md.version "${version}"`);
	}

	const sync = field(block, "sync");
	if (!sync) {
		addError(relativePath, "missing md2md.sync");
	} else if (!/^\d+(m|h|d)$/.test(sync)) {
		addError(relativePath, `invalid md2md.sync "${sync}"`);
	}

	const canonical = field(block, "canonical");
	if (!canonical) {
		addError(relativePath, "missing md2md.canonical");
	} else if (canonical !== expectedCanonical) {
		addError(relativePath, `canonical must be ${expectedCanonical}`);
	}

	const suggestedFile = field(block, "suggested_file");
	if (!suggestedFile) {
		addError(relativePath, "missing md2md.suggested_file");
	} else if (suggestedFile !== filename) {
		addError(relativePath, `suggested_file must be ${filename}`);
	}

	const subscription = field(block, "subscription");
	if (subscription !== "optional") {
		addError(relativePath, 'md2md.subscription must be "optional"');
	}

	const spec = field(block, "spec");
	if (spec !== "https://md2md.md") {
		addError(relativePath, "md2md.spec must be https://md2md.md");
	}

	if (!/^#\s+\S/m.test(body)) {
		addError(relativePath, "body must start with a markdown H1");
	}
}

async function main() {
	const readmeStat = await lstat(join(ROOT, "README.md"));
	if (!readmeStat.isSymbolicLink()) {
		addError("README.md", "must remain a symlink to md2md.md");
	}

	const rootMd2md = await readFile(join(ROOT, "md2md.md"), "utf8");
	const servedMd2md = await readFile(join(MDWIKI_DIR, "md2md.md"), "utf8");
	if (rootMd2md !== servedMd2md) {
		addError("mdwiki/md2md.md", "must match root md2md.md exactly");
	}

	const files = (await readdir(MDWIKI_DIR)).filter((file) => file.endsWith(".md")).sort();
	for (const file of files) {
		const relativePath = `mdwiki/${file}`;
		const content = await readFile(join(MDWIKI_DIR, file), "utf8");
		validateMd2mdDocument(relativePath, content);
	}

	if (errors.length > 0) {
		console.error("md2md validation failed:");
		for (const error of errors) {
			console.error(`- ${error}`);
		}
		process.exitCode = 1;
		return;
	}

	console.log(`validated ${files.length} mdwiki documents`);
}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
