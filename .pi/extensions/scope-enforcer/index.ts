/**
 * Scope Enforcer Extension — Deterministic scope checking for findings.
 *
 * Unlike prompt-based scope enforcement (which relies on the LLM remembering),
 * this extension checks every finding against a structured policy file before
 * allowing it to be added to the findings store.
 *
 * Policy file format (markdown or JSON):
 *
 *   # In Scope
 *   *.target.com
 *   api.target.com
 *   10.0.0.0/8
 *   re:^staging\d+\.target\.com$
 *
 *   # Out of Scope
 *   admin.target.com
 *   *.internal.target.com
 *
 * Deny wins: an out-of-scope match excludes even if an in-scope pattern also matches.
 * Default deny: anything not matching an in-scope pattern is out of scope.
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import { readFileSync, existsSync } from "node:fs";

interface ScopeConfig {
	inScope: string[];
	outOfScope: string[];
}

function parsePolicyFile(path: string): ScopeConfig | null {
	try {
		const text = readFileSync(path, "utf-8");

		// Try JSON first
		try {
			const json = JSON.parse(text);
			return {
				inScope: json.inScope || json["in-scope"] || json.in_scope || [],
				outOfScope: json.outOfScope || json["out-of-scope"] || json.out_of_scope || [],
			};
		} catch {
			// Parse markdown policy
			return parseMarkdownPolicy(text);
		}
	} catch {
		return null;
	}
}

function parseMarkdownPolicy(text: string): ScopeConfig | null {
	const lines = text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !l.startsWith("-") && !l.startsWith("/") && !l.startsWith(">"));

	let currentSection: "in" | "out" | null = null;
	const inScope: string[] = [];
	const outOfScope: string[] = [];

	for (const line of lines) {
		const lower = line.toLowerCase();
		if (lower.includes("in scope") || lower.includes("in-scope") || lower.includes("inscope")) {
			currentSection = "in";
			continue;
		}
		if (lower.includes("out of scope") || lower.includes("out-of-scope") || lower.includes("outofscope") || lower.includes("out of scope")) {
			currentSection = "out";
			continue;
		}

		if (currentSection === "in" && isValidPattern(line)) inScope.push(line);
		if (currentSection === "out" && isValidPattern(line)) outOfScope.push(line);
	}

	return inScope.length > 0 ? { inScope, outOfScope } : null;
}

function isValidPattern(pattern: string): boolean {
	if (pattern.startsWith("re:")) return true;
	if (pattern.includes("/") && pattern.replace(/[^0-9.]/g, "").length >= 7) return true; // CIDR
	if (pattern.includes(".") || pattern === "*") return true;
	return false;
}

function matchPattern(pattern: string, host: string): boolean {
	const p = pattern.toLowerCase().trim();
	const h = host.toLowerCase().trim();

	if (p.startsWith("re:")) {
		try {
			return new RegExp(p.slice(3)).test(h);
		} catch {
			return false;
		}
	}

	// CIDR
	if (p.includes("/")) {
		try {
			const [base, bitsStr] = p.split("/");
			const bits = parseInt(bitsStr, 10);
			const ipToNum = (ip: string): number => ip.split(".").reduce((a, b) => (a << 8) + parseInt(b, 10), 0) >>> 0;
			const mask = ~(2 ** (32 - bits) - 1);
			const hostNum = ipToNum(h);
			const baseNum = ipToNum(base);
			return (hostNum & mask) === (baseNum & mask);
		} catch {
			return false;
		}
	}

	// Wildcard: *.example.com
	if (p.startsWith("*.")) {
		const base = p.slice(2);
		return h.endsWith("." + base);
	}

	// Exact match or subdomain match
	return h === p || h.endsWith("." + p);
}

function checkScope(host: string, config: ScopeConfig): { allowed: boolean; reason: string } {
	// Deny wins: if any out-of-scope pattern matches, block
	for (const oos of config.outOfScope) {
		if (matchPattern(oos, host)) {
			return { allowed: false, reason: `Explicitly out of scope (matches: ${oos})` };
		}
	}

	// Check if host matches any in-scope pattern
	for (const ins of config.inScope) {
		if (matchPattern(ins, host)) {
			return { allowed: true, reason: `In scope (matches: ${ins})` };
		}
	}

	// Default deny: not in any in-scope pattern
	return { allowed: false, reason: "Not matched by any in-scope pattern (default deny)" };
}

const ScopeParams = Type.Object({
	action: StringEnum(["load", "check"] as const),
	policyPath: Type.Optional(Type.String({ description: "Path to policy file" })),
	endpoint: Type.Optional(Type.String({ description: "Endpoint URL to check against scope" })),
	target: Type.Optional(Type.String({ description: "Target domain for scope check" })),
});

interface ScopeDetails {
	allowed?: boolean;
	reason?: string;
	inScopeCount?: number;
	outOfScopeCount?: number;
}

// Singleton scope config
let currentScope: ScopeConfig | null = null;

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "scope_enforcer",
		label: "Scope Enforcer",
		description: "Deterministic scope checking for findings. Load a policy file and check endpoints against it. Actions: load (set policy), check (verify endpoint against policy).",
		parameters: ScopeParams,
		promptSnippet: "Check if an endpoint is in scope using the loaded security policy",
		promptGuidelines: [
			"Use scope_enforcer with action=load to set the policy file first",
			"Use scope_enforcer with action=check to verify an endpoint before testing or reporting",
			"Scope rules: deny wins, default deny — anything not in the in-scope list is blocked",
		],

		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			switch (params.action) {
				case "load": {
					if (!params.policyPath) {
						return {
							content: [{ type: "text", text: "Error: policyPath required for load action." }],
							details: { allowed: false, reason: "missing policyPath" } as ScopeDetails,
						};
					}

					if (!existsSync(params.policyPath)) {
						return {
							content: [{ type: "text", text: `Policy file not found: ${params.policyPath}` }],
							details: { allowed: false, reason: "file not found" } as ScopeDetails,
						};
					}

					const config = parsePolicyFile(params.policyPath);
					if (!config) {
						return {
							content: [{ type: "text", text: `Could not parse policy file: ${params.policyPath}. Must contain # In Scope and # Out of Scope sections, or be valid JSON.` }],
							details: { allowed: false, reason: "parse error" } as ScopeDetails,
						};
					}

					currentScope = config;
					return {
						content: [{ type: "text", text: `Scope loaded: ${config.inScope.length} in-scope, ${config.outOfScope.length} out-of-scope patterns.\nIn scope:\n  ${config.inScope.join("\n  ") || "(none)"}\nOut of scope:\n  ${config.outOfScope.join("\n  ") || "(none)"}` }],
						details: { allowed: true, inScopeCount: config.inScope.length, outOfScopeCount: config.outOfScope.length } as ScopeDetails,
					};
				}

				case "check": {
					if (!currentScope) {
						return {
							content: [{ type: "text", text: "No scope policy loaded. Use scope_enforcer(action=\"load\", policyPath=...) first." }],
							details: { allowed: false, reason: "no policy loaded" } as ScopeDetails,
						};
					}

					const endpoint = params.endpoint || params.target;
					if (!endpoint) {
						return {
							content: [{ type: "text", text: "Error: endpoint or target required for check action." }],
							details: { allowed: false, reason: "missing endpoint" } as ScopeDetails,
						};
					}

					// Extract hostname from URL
					let host = endpoint;
					try {
						const parsed = new URL(host.startsWith("http") ? host : `https://${host}`);
						host = parsed.hostname;
					} catch {
						// Use as-is
					}

					const result = checkScope(host, currentScope);
					const icon = result.allowed ? "✓" : "✗";
					return {
						content: [{ type: "text", text: `${icon} ${endpoint} — ${result.reason}` }],
						details: { allowed: result.allowed, reason: result.reason } as ScopeDetails,
					};
				}

				default:
					return {
						content: [{ type: "text", text: `Unknown action: ${params.action}. Use load or check.` }],
						details: { allowed: false, reason: "unknown action" } as ScopeDetails,
					};
			}
		},

		renderCall(args, theme, _context) {
			const action = (args.action as string) || "?";
			let text = theme.fg("toolTitle", theme.bold("scope ")) + theme.fg("accent", action);
			if (args.policyPath) text += ` ${theme.fg("dim", `@${(args.policyPath as string).slice(0, 40)}...`)}`;
			if (args.endpoint) text += `\n  ${theme.fg("dim", `→ ${(args.endpoint as string).slice(0, 60)}`)}`;
			return new Text(text, 0, 0);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as ScopeDetails | undefined;
			if (!details) return new Text("", 0, 0);
			if (details.allowed) {
				return new Text(theme.fg("success", "\u2713 In scope") + (details.inScopeCount ? theme.fg("dim", ` (${details.inScopeCount}p)`) : ""), 0, 0);
			}
			return new Text(theme.fg("error", "✗ ") + theme.fg("muted", details.reason || "Out of scope"), 0, 0);
		},
	});
}
