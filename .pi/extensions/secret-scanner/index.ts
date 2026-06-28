/**
 * Secret Scanner Extension — Detect leaked secrets in files and HTTP responses.
 *
 * Scans text content for API keys, auth tokens, passwords, private keys,
 * connection strings, and other sensitive data using regex patterns.
 * Useful for finding exposed secrets in JS files, HTML source, config files.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";

const SecretScannerParams = Type.Object({
	text: Type.String({ description: "Text content to scan for secrets" }),
	context: Type.Optional(Type.Boolean({ description: "Show surrounding context. Default: false.", default: false })),
});

interface SecretMatch {
	pattern: string;
	match: string;
	context?: string;
}

interface SecretScanDetails {
	totalSecrets: number;
	byCategory: Record<string, number>;
	severity: "critical" | "high" | "medium" | "low";
}

// Compile comprehensive secret patterns
const SECRET_PATTERNS: { category: string; severity: SecretScanDetails["severity"]; name: string; regex: RegExp }[] = [
	// Critical secrets
	{ category: "api_key", severity: "critical", name: "AWS Access Key", regex: /AKIA[0-9A-Z]{16}/g },
	{ category: "api_key", severity: "critical", name: "AWS Secret Key", regex: /(?<=AWS[_\s]?SECRET[_\s]?(?:ACCESS[_\s]?)?KEY[_\s]?[=:]\s*)[A-Za-z0-9/+=]{40}/gi },
	{ category: "api_key", severity: "critical", name: "GitHub Token", regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/g },
	{ category: "api_key", severity: "critical", name: "GitHub PAT (classic)", regex: /ghp_[A-Za-z0-9_]{36}/g },
	{ category: "api_key", severity: "critical", name: "Google API Key", regex: /AIza[0-9A-Za-z\-_]{35}/g },
	{ category: "api_key", severity: "critical", name: "Slack Token", regex: /xox[baprs]-[A-Za-z0-9\-_]{10,}/g },
	{ category: "api_key", severity: "critical", name: "Stripe Secret Key", regex: /sk_live_[0-9a-zA-Z]{24,}/g },
	{ category: "api_key", severity: "critical", name: "OpenAI API Key", regex: /sk-[A-Za-z0-9]{32,}/g },
	{ category: "api_key", severity: "critical", name: "Twilio API Key", regex: /SK[0-9a-fA-F]{32}/g },
	{ category: "api_key", severity: "critical", name: "SendGrid API Key", regex: /SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{12,}/g },
	{ category: "private_key", severity: "critical", name: "RSA Private Key", regex: /-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----/g },
	{ category: "private_key", severity: "critical", name: "PGP Private Key", regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g },

	// High severity
	{ category: "token", severity: "high", name: "JWT Token", regex: /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g },
	{ category: "token", severity: "high", name: "Bearer Token", regex: /(?:Bearer|Authorization)[\s:=]+([A-Za-z0-9\-_.+/=]{20,})/g },
	{ category: "password", severity: "high", name: "Password Assignment", regex: /(?:password|passwd|pwd|secret)[\s:=]+["']([^"']{4,})["']/gi },
	{ category: "api_key", severity: "high", name: "Generic API Key", regex: /(?:api[_-]?key|apikey|api[_-]?secret)[\s:=]+["']([A-Za-z0-9\-_]{16,})["']/gi },
	{ category: "api_key", severity: "high", name: "Heroku API Key", regex: /[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/g },
	{ category: "api_key", severity: "high", name: "Firebase URL", regex: /[a-z0-9-]+\.firebaseio\.com/g },
	{ category: "connection", severity: "high", name: "Database URL", regex: /(?:mongodb|postgres|mysql|redis|jdbc)[s]?:\/\/[^\s"']+/gi },
	{ category: "connection", severity: "high", name: "S3 Bucket URL", regex: /[a-z0-9.-]+\.s3[.-]?[a-z0-9-]*\.amazonaws\.com/g },

	// Medium severity
	{ category: "token", severity: "medium", name: "CSRF Token", regex: /(?:csrf[_-]?token|_csrf|x-csrf-token)[\s:=]+["']([^"']{8,})["']/gi },
	{ category: "token", severity: "medium", name: "Access Token", regex: /(?:access[_-]?token|auth[_-]?token)[\s:=]+["']([^"']{8,})["']/gi },
	{ category: "info", severity: "medium", name: "Email Address", regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
	{ category: "info", severity: "medium", name: "Internal IP", regex: /(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}/g },
	{ category: "info", severity: "medium", name: "Internal URL", regex: /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?\//g },
	{ category: "config", severity: "medium", name: "Config Endpoint", regex: /https?:\/\/[^\s"']*\.(?:env|config|conf|ini|yaml|yml|json|toml)(?:[?#][^\s"']*)?/gi },
	{ category: "config", severity: "medium", name: "Debug Endpoint", regex: /https?:\/\/[^\s"']*\.(?:phpinfo|server-status|server-info|actuator|swagger)/gi },

	// Low severity
	{ category: "version", severity: "low", name: "Version Number", regex: /(?:version|v)[\s:=]+["']?(\d+\.\d+\.\d+)["']?/gi },
	{ category: "endpoint", severity: "low", name: "API Endpoint", regex: /https?:\/\/[^\s"']*\/(?:api|graphql|v\d+|rest)\/[^\s"']*/gi },
	{ category: "endpoint", severity: "low", name: "Admin Endpoint", regex: /https?:\/\/[^\s"']*\/(?:admin|dashboard|manager|panel|console)/gi },
];

const MAX_OUTPUT_LENGTH = 4096;

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "secret_scanner",
		label: "Secret Scanner",
		description: "Scan text content for leaked secrets: API keys, tokens, passwords, private keys, database URLs, internal IPs, debug endpoints, and more.",
		parameters: SecretScannerParams,
		promptSnippet: "Scan response body or file content for exposed secrets, keys, and sensitive data",
		promptGuidelines: [
			"Use secret_scanner on every JS file, HTML response, and config file you encounter",
			"Scan API responses for leaked tokens or internal data",
			"Run on robots.txt, sitemap.xml, and .well-known/ responses",
			"Focus on files from CDNs, bundles, and source maps — they often leak keys",
			"Pair with grep for manual follow-up on interesting patterns",
		],

		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			const text = params.text;
			const showContext = params.context ?? false;
			const matches: SecretMatch[] = [];
			const byCategory: Record<string, number> = {};
			let highestSeverity: SecretScanDetails["severity"] = "low";

			for (const pattern of SECRET_PATTERNS) {
				pattern.regex.lastIndex = 0;
				let match: RegExpExecArray | null;
				while ((match = pattern.regex.exec(text)) !== null) {
					const found = match[1] || match[0];
					let context = "";
					if (showContext) {
						const idx = match.index;
						const start = Math.max(0, idx - 40);
						const end = Math.min(text.length, idx + found.length + 40);
						context = text.slice(start, end).replace(/\n/g, "\\n");
					}
					matches.push({ pattern: pattern.name, match: found, context });
					byCategory[pattern.category] = (byCategory[pattern.category] || 0) + 1;

					// Track highest severity
					const sevRank = { critical: 4, high: 3, medium: 2, low: 1 };
					if (sevRank[pattern.severity] > sevRank[highestSeverity]) {
						highestSeverity = pattern.severity;
					}
				}
			}

			// Deduplicate matches
			const seen = new Set<string>();
			const unique = matches.filter((m) => {
				const key = `${m.pattern}:${m.match}`;
				if (seen.has(key)) return false;
				seen.add(key);
				return true;
			});

			if (unique.length === 0) {
				return {
					content: [{ type: "text", text: "No secrets detected in the provided content." }],
					details: { totalSecrets: 0, byCategory: {}, severity: "low" } as SecretScanDetails,
				};
			}

			// Group by category/severity for output
			const critical = unique.filter((m) => SECRET_PATTERNS.find(p => p.name === m.pattern)?.severity === "critical");
			const high = unique.filter((m) => SECRET_PATTERNS.find(p => p.name === m.pattern)?.severity === "high");
			const medium = unique.filter((m) => SECRET_PATTERNS.find(p => p.name === m.pattern)?.severity === "medium");
			const low = unique.filter((m) => SECRET_PATTERNS.find(p => p.name === m.pattern)?.severity === "low");

			let output = `Found ${unique.length} potential secrets (${critical.length} critical, ${high.length} high, ${medium.length} medium, ${low.length} low)\n\n`;

			const renderSection = (label: string, items: SecretMatch[], max: number) => {
				if (items.length === 0) return "";
				let section = `## ${label}\n\n`;
				for (const item of items.slice(0, max)) {
					const redacted = item.match.length > 8
						? item.match.slice(0, 4) + "..." + item.match.slice(-4)
						: item.match;
					section += `- **${item.pattern}**: \`${redacted}\``;
					if (item.context) {
						section += `\n  → ${item.context}`;
					}
					section += "\n";
				}
				if (items.length > max) {
					section += `  ... ${items.length - max} more\n`;
				}
				return section + "\n";
			};

			output += renderSection("CRITICAL", critical, 10);
			output += renderSection("HIGH", high, 8);
			output += renderSection("MEDIUM", medium, 5);
			output += renderSection("LOW", low, 5);

			if (output.length > MAX_OUTPUT_LENGTH) {
				output = output.slice(0, MAX_OUTPUT_LENGTH) + `\n\n... [truncated at ${MAX_OUTPUT_LENGTH} chars, ${unique.length} total matches]`;
			}

			return {
				content: [{ type: "text", text: output }],
				details: {
					totalSecrets: unique.length,
					byCategory,
					severity: highestSeverity,
				} as SecretScanDetails,
			};
		},

		renderCall(args, theme, _context) {
			const textLength = ((args.text as string) || "").length;
			let text = theme.fg("toolTitle", theme.bold("secret_scanner ")) +
				theme.fg("muted", `scanning ${(textLength / 1024).toFixed(1)}KB of text`);
			return new Text(text, 0, 0);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as SecretScanDetails | undefined;
			if (!details) return new Text("", 0, 0);
			if (details.totalSecrets === 0) {
				return new Text(theme.fg("success", "✓ ") + theme.fg("muted", "No secrets found"), 0, 0);
			}
			const sevColor =
				details.severity === "critical" ? "error" :
				details.severity === "high" ? "warning" :
				details.severity === "medium" ? "accent" : "dim";
			const cats = Object.entries(details.byCategory)
				.map(([k, v]) => `${k}:${v}`)
				.join(" ");
			return new Text(
				theme.fg(sevColor, `${details.totalSecrets} secrets found `) +
					theme.fg("muted", cats),
				0,
				0,
			);
		},
	});
}
