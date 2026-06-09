interface Env {
	MD_CONTENT: KVNamespace;
}

const CORS_HEADERS = {
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
	"Access-Control-Allow-Headers": "If-None-Match",
};

const GOBLIN_HOST = "goblin.md";
const GOBLIN_CARD_KEY = "asset:goblin-card.png";
const GOBLIN_CARD_PATHS = new Set(["/card.png", "/goblin-card.png", "/og.png", "/preview.png"]);
const SOCIAL_CRAWLER_PATTERN =
	/(twitterbot|facebookexternalhit|facebot|slackbot|discordbot|linkedinbot|telegrambot|whatsapp|applebot)/i;

function markdownHeaders(etag: string): Headers {
	const headers = new Headers({
		"Content-Type": "text/markdown; charset=utf-8",
		"Cache-Control": "public, max-age=300",
		"X-Content-Type-Options": "nosniff",
		...CORS_HEADERS,
	});

	if (etag) {
		headers.set("ETag", etag);
	}

	return headers;
}

function htmlHeaders(): Headers {
	return new Headers({
		"Content-Type": "text/html; charset=utf-8",
		"Cache-Control": "public, max-age=300",
		"X-Content-Type-Options": "nosniff",
		...CORS_HEADERS,
	});
}

function pngHeaders(): Headers {
	return new Headers({
		"Content-Type": "image/png",
		"Cache-Control": "public, max-age=86400, immutable",
		"X-Content-Type-Options": "nosniff",
		...CORS_HEADERS,
	});
}

function textHeaders(): Headers {
	return new Headers({
		"Content-Type": "text/plain; charset=utf-8",
		"X-Content-Type-Options": "nosniff",
		...CORS_HEADERS,
	});
}

function etagMatches(ifNoneMatch: string | null, etag: string): boolean {
	if (!ifNoneMatch || !etag) return false;

	return ifNoneMatch.split(",").some((candidate) => {
		const normalized = candidate.trim().replace(/^W\//, "");
		return normalized === "*" || normalized === etag;
	});
}

function isGoblinSocialCardRequest(request: Request, host: string, url: URL): boolean {
	if (host !== GOBLIN_HOST) return false;

	if (url.pathname === "/card" || url.searchParams.get("card") === "1") {
		return true;
	}

	const userAgent = request.headers.get("User-Agent") ?? "";
	return url.pathname === "/" && SOCIAL_CRAWLER_PATTERN.test(userAgent);
}

function goblinSocialCardHtml(): string {
	const title = "goblin.md";
	const description = "Never talk about goblins, unless it is absolutely and unambiguously relevant.";
	const canonicalUrl = "https://goblin.md/";
	const imageUrl = "https://goblin.md/card.png?v=low1";
	const imageAlt = "Terminal-style ASCII output misclassified as a unicorn.";

	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<meta name="description" content="${description}">
<link rel="canonical" href="${canonicalUrl}">
<meta property="og:type" content="website">
<meta property="og:url" content="${canonicalUrl}">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description}">
<meta property="og:image" content="${imageUrl}">
<meta property="og:image:secure_url" content="${imageUrl}">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="${imageAlt}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${title}">
<meta name="twitter:description" content="${description}">
<meta name="twitter:image" content="${imageUrl}">
<meta name="twitter:image:alt" content="${imageAlt}">
</head>
<body>
<pre>https://goblin.md</pre>
</body>
</html>
`;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		if (request.method === "OPTIONS") {
			return new Response(null, {
				status: 204,
				headers: CORS_HEADERS,
			});
		}

		if (request.method !== "GET" && request.method !== "HEAD") {
			const headers = textHeaders();
			headers.set("Allow", "GET, HEAD, OPTIONS");

			return new Response(`method ${request.method} not allowed\n`, {
				status: 405,
				headers,
			});
		}

		const url = new URL(request.url);
		const host = url.hostname.replace(/^www\./, "");

		// Derive KV key from hostname: "soc2.md" → "soc2", "md2md.md" → "md2md"
		const key = host.endsWith(".md") ? host.slice(0, -3) : host;

		if (host === GOBLIN_HOST && GOBLIN_CARD_PATHS.has(url.pathname)) {
			const image = await env.MD_CONTENT.get(GOBLIN_CARD_KEY, "arrayBuffer");

			if (image === null) {
				return new Response(request.method === "HEAD" ? null : "card image not found\n", {
					status: 404,
					headers: textHeaders(),
				});
			}

			return new Response(request.method === "HEAD" ? null : image, {
				headers: pngHeaders(),
			});
		}

		if (isGoblinSocialCardRequest(request, host, url)) {
			return new Response(request.method === "HEAD" ? null : goblinSocialCardHtml(), {
				headers: htmlHeaders(),
			});
		}

		const { value, metadata } = await env.MD_CONTENT.getWithMetadata<{
			etag: string;
		}>(key);

		if (value === null) {
			return new Response(request.method === "HEAD" ? null : `no content found for ${host}\n`, {
				status: 404,
				headers: textHeaders(),
			});
		}

		const etag = metadata?.etag ?? "";
		const headers = markdownHeaders(etag);

		// Support conditional requests for md2md sync protocol
		const ifNoneMatch = request.headers.get("If-None-Match");
		if (etagMatches(ifNoneMatch, etag)) {
			return new Response(null, {
				status: 304,
				headers,
			});
		}

		if (request.method === "HEAD") {
			return new Response(null, { headers });
		}

		return new Response(value, {
			headers,
		});
	},
} satisfies ExportedHandler<Env>;
