/**
 * Burp Client Extension — Automates HTTP requests through Burp Suite's REST API.
 *
 * Sends requests through Burp Proxy/Repeater so that all traffic is captured
 * for manual review. Also supports Collaborator for blind/out-of-band testing,
 * and scope management.
 *
 * Requires Burp Suite Professional with REST API enabled.
 * Default: http://127.0.0.1:1337 (configurable via BURP_API_URL env var)
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";

const BURP_API = process.env["BURP_API_URL"] || "http://127.0.0.1:1337";

interface BurpResponse {
	status: number;
	body: string;
	headers: Record<string, string>;
}

async function burpFetch(path: string, options: { method?: string; body?: string } = {}): Promise<BurpResponse> {
	const url = `${BURP_API}${path}`;
	const res = await fetch(url, {
		method: options.method || "GET",
		headers: { "Content-Type": "application/json" },
		body: options.body,
	});
	const headers: Record<string, string> = {};
	res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
	return {
		status: res.status,
		body: await res.text(),
		headers,
	};
}

const BurpParams = Type.Object({
	action: StringEnum(["send", "collaborator", "scope", "history", "check"] as const),
	url: Type.Optional(Type.String({ description: "URL to send through Burp" })),
	method: Type.Optional(StringEnum(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"] as const, { default: "GET" })),
	headers: Type.Optional(Type.String({ description: "HTTP headers as JSON string" })),
	body: Type.Optional(Type.String({ description: "Request body" })),
	base64Request: Type.Optional(Type.String({ description: "Base64-encoded raw HTTP request for Repeater" })),
	maxEntries: Type.Optional(Type.Number({ description: "Max history entries to return" })),
});

interface BurpDetails {
	action: string;
	status?: number;
	error?: string;
	entryCount?: number;
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "burp_client",
		label: "Burp Suite Client",
		description: "Automate HTTP requests through Burp Suite's REST API. Use for blind/out-of-band testing (Collaborator), sending requests through Burp proxy, managing scope, and reviewing proxy history. Requires Burp Suite Pro with REST API on port 1337.",
		parameters: BurpParams,
		promptSnippet: "Send HTTP request through Burp Suite or get Collaborator interactions",
		promptGuidelines: [
			"Use burp_client for requests that need to go through Burp proxy for manual review",
			"Use burp_client action=collaborator for blind XSS, SSRF, and out-of-band testing",
			"Use burp_client action=check to verify Burp API is running",
			"Burp must be running with REST API enabled on port 1337",
		],

		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			switch (params.action) {
				case "check": {
					try {
						const resp = await burpFetch("/");
						return {
							content: [{ type: "text", text: resp.status === 200
								? `Burp Suite API available at ${BURP_API}`
								: `Burp API responded with status ${resp.status}` }],
							details: { action: "check", status: resp.status } as BurpDetails,
						};
					} catch (err: unknown) {
						const msg = err instanceof Error ? err.message : String(err);
						return {
							content: [{ type: "text", text: `Burp API unreachable at ${BURP_API}: ${msg}\nStart Burp Suite Pro with REST API enabled.` }],
							details: { action: "check", error: msg } as BurpDetails,
						};
					}
				}

				case "send": {
					if (!params.url) {
						return {
							content: [{ type: "text", text: "Error: url required for send action." }],
							details: { action: "send", error: "missing url" } as BurpDetails,
						};
					}

					const parsedHeaders: Record<string, string> = {};
					if (params.headers) {
						try { Object.assign(parsedHeaders, JSON.parse(params.headers)); }
						catch { return { content: [{ type: "text", text: "Error: invalid headers JSON." }], details: { action: "send", error: "invalid headers" } as BurpDetails }; }
					}

					const payload = {
						url: params.url,
						method: params.method || "GET",
						headers: { ...parsedHeaders, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
						body: params.body || "",
					};

					try {
						const resp = await burpFetch("/burp/repeater", {
							method: "POST",
							body: JSON.stringify(payload),
						});
						return {
							content: [{ type: "text", text: `Sent through Burp: ${params.method || "GET"} ${params.url}\nStatus: ${resp.status}` }],
							details: { action: "send", status: resp.status } as BurpDetails,
						};
					} catch (err: unknown) {
						const msg = err instanceof Error ? err.message : String(err);
						return {
							content: [{ type: "text", text: `Burp error: ${msg}` }],
							details: { action: "send", error: msg } as BurpDetails,
						};
					}
				}

				case "collaborator": {
					try {
						const resp = await burpFetch("/burp/collaborator");
						if (resp.status === 200) {
							return {
								content: [{ type: "text", text: `Collaborator interactions: ${resp.body.slice(0, 2000)}` }],
								details: { action: "collaborator", status: 200 } as BurpDetails,
							};
						}
						return {
							content: [{ type: "text", text: "No Collaborator interactions yet, or Burp API returned unexpected response." }],
							details: { action: "collaborator", status: resp.status } as BurpDetails,
						};
					} catch (err: unknown) {
						const msg = err instanceof Error ? err.message : String(err);
						return {
							content: [{ type: "text", text: `Collaborator error: ${msg}` }],
							details: { action: "collaborator", error: msg } as BurpDetails,
						};
					}
				}

				case "scope": {
					try {
						const resp = await burpFetch("/burp/target/scope");
						return {
							content: [{ type: "text", text: `Burp scope:\n${resp.body.slice(0, 2000)}` }],
							details: { action: "scope", status: resp.status } as BurpDetails,
						};
					} catch (err: unknown) {
						const msg = err instanceof Error ? err.message : String(err);
						return {
							content: [{ type: "text", text: `Scope error: ${msg}` }],
							details: { action: "scope", error: msg } as BurpDetails,
						};
					}
				}

				case "history": {
					try {
						const max = params.maxEntries || 50;
						const resp = await burpFetch(`/burp/proxy/http_history?max=${max}`);
						return {
							content: [{ type: "text", text: `Proxy history (last ${max}):\n${resp.body.slice(0, 3000)}` }],
							details: { action: "history", status: resp.status, entryCount: max } as BurpDetails,
						};
					} catch (err: unknown) {
						const msg = err instanceof Error ? err.message : String(err);
						return {
							content: [{ type: "text", text: `History error: ${msg}` }],
							details: { action: "history", error: msg } as BurpDetails,
						};
					}
				}

				default:
					return {
						content: [{ type: "text", text: `Unknown action: ${params.action}. Use send, collaborator, scope, history, or check.` }],
						details: { action: params.action, error: "unknown action" } as BurpDetails,
					};
			}
		},

		renderCall(args, theme, _context) {
			const action = (args.action as string) || "?";
			let text = theme.fg("toolTitle", theme.bold("burp ")) + theme.fg("accent", action);
			if (args.url) text += `\n  ${theme.fg("dim", (args.url as string).slice(0, 60))}`;
			return new Text(text, 0, 0);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as BurpDetails | undefined;
			if (!details) return new Text("", 0, 0);
			if (details.error) return new Text(theme.fg("error", "✗ ") + theme.fg("muted", details.error), 0, 0);
			return new Text(theme.fg("success", "✓ ") + theme.fg("dim", details.action), 0, 0);
		},
	});
}
