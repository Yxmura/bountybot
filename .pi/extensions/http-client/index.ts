/**
 * HTTP Client Extension — Programmatic HTTP requests with session support.
 *
 * Provides a `http_request` tool that makes HTTP requests programmatically.
 * Unlike raw bash/curl, this tool manages cookies automatically, handles
 * redirects, and supports complex request patterns (multipart, JSON bodies,
 * custom headers). Useful for authenticated testing and API interaction.
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";

const MethodEnum = StringEnum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const);

interface HttpRequestParams {
	method: string;
	url: string;
	headers?: string;
	body?: string;
	followRedirects?: boolean;
	timeout?: number;
	extractPattern?: string;
	extractJsonField?: string;
}

const HttpRequestParams = Type.Object({
	method: MethodEnum,
	url: Type.String({ description: "Target URL" }),
	headers: Type.Optional(Type.String({ description: "HTTP headers as JSON object string" })),
	body: Type.Optional(Type.String({ description: "Request body (raw string, JSON, or form-encoded)" })),
	followRedirects: Type.Optional(Type.Boolean({ description: "Follow 3xx redirects. Default: true.", default: true })),
	timeout: Type.Optional(Type.Number({ description: "Request timeout in ms. Default: 30000.", default: 30000 })),
	extractPattern: Type.Optional(Type.String({ description: "Regex pattern to extract from response body" })),
	extractJsonField: Type.Optional(Type.String({ description: "Dot-notation JSON field path to extract (e.g. data.user.token)" })),
});

interface HttpResponse {
	status: number;
	statusText: string;
	headers: Record<string, string>;
	body: string;
	bodySize: number;
	redirected: boolean;
	finalUrl: string;
	duration: number;
}

interface HttpRequestDetails {
	url: string;
	method: string;
	status: number;
	duration: number;
	size: number;
	cookiesReceived: number;
	error?: string;
}

// In-memory cookie jar for session persistence
const cookieJar: Map<string, string> = new Map();

// Rate limiting: max 5 requests per second (200ms between requests)
const MIN_REQUEST_INTERVAL_MS = 200;
let lastRequestTime = 0;

async function enforceRateLimit(): Promise<void> {
	const now = Date.now();
	const elapsed = now - lastRequestTime;
	if (elapsed < MIN_REQUEST_INTERVAL_MS) {
		await new Promise((resolve) => setTimeout(resolve, MIN_REQUEST_INTERVAL_MS - elapsed));
	}
	lastRequestTime = Date.now();
}

function parseCookiesFromHeaders(headers: Record<string, string>, domain: string): void {
	const setCookie = headers["set-cookie"];
	if (!setCookie) return;
	const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
	for (const cookieStr of cookies) {
		const parts = cookieStr.split(";")[0];
		if (!parts) continue;
		const eqIdx = parts.indexOf("=");
		if (eqIdx < 0) continue;
		const name = parts.slice(0, eqIdx).trim();
		const value = parts.slice(eqIdx + 1).trim();
		const key = `${domain}|${name}`;
		cookieJar.set(key, value);
	}
}

function getCookiesForUrl(url: string): string {
	try {
		const u = new URL(url);
		const domain = u.hostname;
		return Array.from(cookieJar.entries())
			.filter(([k]) => {
				const storedDomain = k.split("|")[0];
				return domain.endsWith(storedDomain) || storedDomain.endsWith(domain);
			})
			.map(([k, v]) => `${k.split("|")[1]}=${v}`)
			.join("; ");
	} catch {
		return "";
	}
}

async function makeRequest(params: HttpRequestParams): Promise<{ response: HttpResponse; details: HttpRequestDetails }> {
	const { method, url, headers: headersJson, body, followRedirects, timeout } = params;
	const start = Date.now();

	await enforceRateLimit();

	let parsedHeaders: Record<string, string> = {};
	if (headersJson) {
		try {
			parsedHeaders = JSON.parse(headersJson);
		} catch {
			return {
				response: { status: 0, statusText: "Invalid headers JSON", headers: {}, body: "", bodySize: 0, redirected: false, finalUrl: url, duration: 0 },
				details: { url, method, status: 0, duration: 0, size: 0, cookiesReceived: 0, error: "Invalid headers JSON" },
			};
		}
	}

	// Inject session cookies if available
	const sessionCookies = getCookiesForUrl(url);
	if (sessionCookies) {
		const existingCookie = parsedHeaders["Cookie"] || parsedHeaders["cookie"] || "";
		parsedHeaders["Cookie"] = existingCookie ? `${existingCookie}; ${sessionCookies}` : sessionCookies;
	}

	const headersInit: Record<string, string> = {
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5",
		...parsedHeaders,
	};

	if (body && !headersInit["Content-Type"]) {
		// Auto-detect content type
		if (body.trim().startsWith("{") || body.trim().startsWith("[")) {
			headersInit["Content-Type"] = "application/json";
		} else if (body.includes("=") && !body.includes("<")) {
			headersInit["Content-Type"] = "application/x-www-form-urlencoded";
		}
	}

	const controller = new AbortController();
	const timeoutMs = timeout || 30000;
	const timer = setTimeout(() => controller.abort(), timeoutMs);

	try {
		const fetchInit: RequestInit = {
			method,
			headers: headersInit,
			signal: controller.signal,
		};
		if (body && method !== "GET" && method !== "HEAD") {
			fetchInit.body = body;
		}
		if (!followRedirects && followRedirects !== undefined) {
			fetchInit.redirect = "manual";
		}

		const res = await fetch(url, fetchInit);
		clearTimeout(timer);

		const responseHeaders: Record<string, string> = {};
		res.headers.forEach((value, key) => {
			responseHeaders[key.toLowerCase()] = value;
		});

		const responseBody = await res.text();
		const duration = Date.now() - start;
		const bodySize = Buffer.byteLength(responseBody, "utf-8");

		parseCookiesFromHeaders(responseHeaders, new URL(url).hostname);

		const response: HttpResponse = {
			status: res.status,
			statusText: res.statusText,
			headers: responseHeaders,
			body: responseBody,
			bodySize,
			redirected: res.redirected,
			finalUrl: res.url,
			duration,
		};

		return {
			response,
			details: {
				url,
				method,
				status: res.status,
				duration,
				size: bodySize,
				cookiesReceived: cookieJar.size,
			},
		};
	} catch (err: unknown) {
		clearTimeout(timer);
		const duration = Date.now() - start;
		const msg = err instanceof Error ? err.message : String(err);
		let errorMsg = msg;
		if (msg.includes("aborted") || msg.includes("timeout")) {
			errorMsg = `Request timed out after ${timeoutMs}ms`;
		}
		return {
			response: { status: 0, statusText: "Error", headers: {}, body: errorMsg, bodySize: 0, redirected: false, finalUrl: url, duration },
			details: { url, method, status: 0, duration, size: 0, cookiesReceived: 0, error: errorMsg },
		};
	}
}

function truncateBody(body: string, maxLen: number): string {
	if (body.length <= maxLen) return body;
	return body.slice(0, maxLen) + `\n\n... [${body.length - maxLen} more bytes]`;
}

function extractFromBody(body: string, pattern?: string, jsonField?: string): string {
	if (pattern) {
		try {
			const re = new RegExp(pattern, "gs");
			const matches = body.match(re);
			if (matches && matches.length > 0) {
				return `Extracted ${matches.length} matches:\n${matches.map((m, i) => `[${i + 1}] ${m.trim().slice(0, 200)}`).join("\n")}`;
			}
			return "No matches found for pattern.";
		} catch {
			return "Invalid regex pattern.";
		}
	}
	if (jsonField) {
		try {
			const obj = JSON.parse(body) as Record<string, unknown>;
			const parts = jsonField.split(".");
			let current: unknown = obj;
			for (const part of parts) {
				if (current === undefined || current === null) return `Field "${jsonField}" not found.`;
				current = (current as Record<string, unknown>)[part];
			}
			return typeof current === "string" ? current : JSON.stringify(current, null, 2);
		} catch {
			return "Could not parse response as JSON or field not found.";
		}
	}
	return "";
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "http_request",
		label: "HTTP Client",
		description: "Make HTTP requests with automatic cookie session management. Supports GET/POST/PUT/DELETE, custom headers (as JSON), body, redirect control, regex extraction, and JSON field extraction.",
		parameters: HttpRequestParams,
		promptSnippet: "Send HTTP request to url with optional custom headers, body, and response extraction",
		promptGuidelines: [
			"Use http_request for API testing, parameter fuzzing, and authenticated requests",
			"Pass headers as a JSON string: {\"Authorization\":\"Bearer ...\",\"Content-Type\":\"application/json\"}",
			"Cookies are automatically saved between requests — use for session-based testing",
			"Use extractPattern to pull specific values from responses (tokens, CSRF, hidden fields)",
			"Use extractJsonField with dot notation: 'data.user.token', 'access_token'",
			"Set followRedirects=false to inspect 302/301 redirects for open redirect testing",
			"For file upload / multipart, use bash + curl instead",
		],

		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			const { response, details } = await makeRequest(params);

			if (details.error) {
				return {
					content: [{ type: "text", text: `Error: ${details.error}` }],
					details,
				};
			}

			const extracted = extractFromBody(response.body, params.extractPattern, params.extractJsonField);

			let output = `HTTP ${response.status} ${response.statusText} — ${response.duration}ms — ${response.bodySize}B\n`;
			output += `Final URL: ${response.finalUrl}\n`;

			// Show key response headers
			const keyHeaders = ["content-type", "server", "x-powered-by", "content-length", "set-cookie", "location", "www-authenticate", "x-frame-options", "content-security-policy", "access-control-allow-origin", "x-csrf-token"];
			const interesting: string[] = [];
			for (const [k, v] of Object.entries(response.headers)) {
				if (keyHeaders.includes(k) || k.startsWith("x-")) {
					interesting.push(`  ${k}: ${v}`);
				}
			}
			if (interesting.length > 0) {
				output += `\nKey Headers:\n${interesting.join("\n")}\n`;
			}

			if (extracted) {
				output += `\nExtracted:\n${extracted}\n`;
			}

			// Truncate body for output
			const maxBodyShow = params.extractPattern || params.extractJsonField ? 500 : 2000;
			output += `\nResponse Body (${response.bodySize}B):\n${truncateBody(response.body, maxBodyShow)}`;

			if (response.redirected) {
				output += `\n\nRedirected to: ${response.finalUrl}`;
			}

			return {
				content: [{ type: "text", text: output }],
				details,
			};
		},

		renderCall(args, theme, _context) {
			const method = (args.method as string) || "GET";
			const url = (args.url as string) || "...";
			const methodColor = {
				GET: "success",
				POST: "accent",
				PUT: "warning",
				PATCH: "warning",
				DELETE: "error",
				HEAD: "dim",
				OPTIONS: "dim",
			}[method] || "muted";
			const shortUrl = url.length > 50 ? url.slice(0, 50) + "..." : url;
			let text = theme.fg("toolTitle", theme.bold("http ")) +
				theme.fg(methodColor, method) +
				" " +
				theme.fg("accent", shortUrl);
			if (args.headers) {
				const hdrs: Record<string, string> = {};
				try { Object.assign(hdrs, JSON.parse(args.headers as string)); } catch { /* ignore */ }
				const hdrKeys = Object.keys(hdrs).filter(k => k.toLowerCase() !== "cookie");
				if (hdrKeys.length > 0) {
					text += `\n  ${theme.fg("dim", hdrKeys.join(", "))}`;
				}
			}
			return new Text(text, 0, 0);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as HttpRequestDetails | undefined;
			if (!details) {
				const text = result.content[0];
				return new Text(text?.type === "text" ? text.text.slice(0, 100) : "", 0, 0);
			}
			if (details.error) {
				return new Text(theme.fg("error", `✗ ${details.error}`), 0, 0);
			}
			const statusColor =
				details.status >= 200 && details.status < 300 ? "success" :
				details.status >= 300 && details.status < 400 ? "warning" :
				details.status >= 400 && details.status < 500 ? "error" :
				details.status >= 500 ? "error" : "muted";
			return new Text(
				theme.fg("success", "✓ ") +
					theme.fg(statusColor, `${details.status}`) +
					theme.fg("muted", ` ${details.method} ${details.url.slice(0, 40)} `) +
					theme.fg("dim", `${details.duration}ms ${(details.size / 1024).toFixed(1)}KB`),
				0,
				0,
			);
		},
	});

	// /cookies command to view session cookies
	pi.registerCommand("cookies", {
		description: "View captured session cookies from http_request",
		handler: async (_args, ctx) => {
			if (cookieJar.size === 0) {
				ctx.ui.notify("No cookies in session jar. Make some http_request calls first.", "info");
				return;
			}
			const lines: string[] = [`${cookieJar.size} cookies in session:`];
			for (const [k, v] of cookieJar.entries()) {
				const [domain, name] = k.split("|");
				const preview = v.length > 40 ? v.slice(0, 40) + "..." : v;
				lines.push(`  ${domain}: ${name}=${preview}`);
			}
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
