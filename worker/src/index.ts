interface Env {
	MD_CONTENT: KVNamespace;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		const host = url.hostname.replace(/^www\./, "");

		// Derive KV key from hostname: "soc2.md" → "soc2", "md2md.md" → "md2md"
		const key = host.endsWith(".md") ? host.slice(0, -3) : host;

		const { value, metadata } = await env.MD_CONTENT.getWithMetadata<{
			etag: string;
		}>(key);

		if (value === null) {
			return new Response(`no content found for ${host}\n`, {
				status: 404,
				headers: { "Content-Type": "text/plain; charset=utf-8" },
			});
		}

		const etag = metadata?.etag ?? "";

		// Support conditional requests for md2md sync protocol
		const ifNoneMatch = request.headers.get("If-None-Match");
		if (ifNoneMatch && ifNoneMatch === etag) {
			return new Response(null, {
				status: 304,
				headers: { ETag: etag },
			});
		}

		return new Response(value, {
			headers: {
				"Content-Type": "text/markdown; charset=utf-8",
				ETag: etag,
				"Cache-Control": "public, max-age=300",
				"Access-Control-Allow-Origin": "*",
			},
		});
	},
} satisfies ExportedHandler<Env>;
