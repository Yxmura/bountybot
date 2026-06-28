/**
 * Findings Context Extension — Structured finding store with chain suggestions.
 *
 * The single source of truth for an audit. Every agent writes findings here
 * so the next agent can pick up where the last left off. Includes a chain
 * suggestion engine that recommends exploit chains based on finding types.
 *
 * Ported from Trapframe findings-context tool and extended for Pi.
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import { writeFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const STORE_DIR = ".trapframe";
const STORE_FILE = "findings.json";

const VULN_TYPES = [
	"sqli", "xss", "ssrf", "idor", "rce", "ato", "cache-poison",
	"race-condition", "open-redirect", "cors", "oauth", "jwt",
	"info-disclosure", "misconfig", "template-injection", "xxe",
	"ldap", "command-injection", "file-read", "file-upload",
	"csrf", "nosqli", "hpp", "host-header", "subdomain-takeover",
	"broken-auth", "rate-limit", "business-logic",
];

interface Finding {
	id: string;
	title: string;
	severity: string;
	type: string;
	endpoint: string;
	cwe: string;
	description: string;
	poc: string;
	evidence: string;
	remediation: string;
	cvssScore: number;
	cvssVector: string;
	policyCheck?: string;
	chainWith: string[];
	tags: string[];
	timestamp: number;
	status: string;
}

interface TelemetryEntry {
	id: string;
	type: string;
	message: string;
	endpoint?: string;
	severity?: string;
	tags: string[];
	timestamp: number;
}

interface Flag {
	endpoint: string;
	reason: string;
	count: number;
	firstFlagged: number;
	lastFlagged: number;
	severity: string;
}

interface FindingsStore {
	session: {
		target: string;
		startTime: number;
		state: string;
		phase: number;
		notes: string;
	};
	findings: Finding[];
	telemetry: TelemetryEntry[];
	flags: Flag[];
	phases: Record<string, { complete: boolean; count: number }>;
	policyPath?: string;
}

const INITIAL_STORE: FindingsStore = {
	session: { target: "", startTime: Date.now(), state: "planning", phase: 0, notes: "" },
	findings: [],
	telemetry: [],
	flags: [],
	phases: {
		recon: { complete: false, count: 0 },
		fuzzing: { complete: false, count: 0 },
		exploitation: { complete: false, count: 0 },
		chaining: { complete: false, count: 0 },
		verification: { complete: false, count: 0 },
	},
};

const CHAIN_MAP: Record<string, string[]> = {
	"open-redirect": ["oauth", "ato", "csrf"],
	xss: ["csrf", "ato", "cache-poison"],
	"cache-poison": ["xss", "open-redirect"],
	ssrf: ["rce", "info-disclosure", "ato"],
	idor: ["ato", "business-logic", "info-disclosure"],
	csrf: ["xss", "ato"],
	"race-condition": ["business-logic", "ato"],
	"broken-auth": ["ato", "idor"],
	oauth: ["ato", "open-redirect"],
	sqli: ["rce", "info-disclosure"],
	rce: ["ato", "info-disclosure"],
	"command-injection": ["rce", "info-disclosure"],
};

function sevOrd(s: string) {
	return ["critical", "high", "medium", "low", "info"].indexOf(s);
}

function cmpSev(a: Finding, b: Finding) {
	return (b.cvssScore || 0) - (a.cvssScore || 0) || sevOrd(a.severity) - sevOrd(b.severity);
}

function genId(prefix: string) {
	return `${prefix}-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
}

function getStorePath(cwd: string): string {
	const dir = join(cwd, STORE_DIR);
	if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
	return join(dir, STORE_FILE);
}

function readStore(fp: string): FindingsStore {
	try {
		return JSON.parse(readFileSync(fp, "utf-8"));
	} catch {
		return JSON.parse(JSON.stringify(INITIAL_STORE));
	}
}

function getSuggestions(findings: Finding[]): string[] {
	const types = [...new Set(findings.map((f) => f.type).filter(Boolean))];
	const sug: string[] = [];
	for (const t of types) {
		const chains = CHAIN_MAP[t] || [];
		for (const c of chains) {
			if (types.includes(c)) {
				const a = findings.filter((f) => f.type === t).map((f) => f.title);
				const b = findings.filter((f) => f.type === c).map((f) => f.title);
				sug.push(`${t} + ${c}: ${a[0]?.slice(0, 40)} → ${b[0]?.slice(0, 40)}`);
			}
		}
	}
	return [...new Set(sug)];
}

const FindingsParams = Type.Object({
	action: StringEnum([
		"add", "update", "delete", "get", "list", "status",
		"suggest", "timeline", "export", "clear",
		"chain-add", "set-target", "log", "flag", "note",
		"set-policy", "check-policy", "phase",
	] as const),
	// Finding fields
	findingId: Type.Optional(Type.String({ description: "Finding ID for update/delete/get/chain-add" })),
	title: Type.Optional(Type.String({ description: "Finding title" })),
	severity: Type.Optional(StringEnum(["critical", "high", "medium", "low", "info"] as const, { description: "Severity level" })),
	type: Type.Optional(Type.String({ description: "Vuln type: sqli, xss, ssrf, idor, rce, ato, cache-poison, etc." })),
	endpoint: Type.Optional(Type.String({ description: "Affected URL or endpoint" })),
	cwe: Type.Optional(Type.String({ description: "CWE identifier (e.g. CWE-79)" })),
	description: Type.Optional(Type.String({ description: "Vulnerability description" })),
	poc: Type.Optional(Type.String({ description: "Proof of concept" })),
	evidence: Type.Optional(Type.String({ description: "Evidence data" })),
	remediation: Type.Optional(Type.String({ description: "Fix recommendation" })),
	cvssScore: Type.Optional(Type.Number({ description: "CVSS 3.1 numerical score" })),
	cvssVector: Type.Optional(Type.String({ description: "CVSS 3.1 vector string" })),
	chainWith: Type.Optional(Type.String({ description: "Comma-separated finding IDs to chain" })),
	tags: Type.Optional(Type.String({ description: "Comma-separated tags" })),
	status: Type.Optional(StringEnum(["open", "confirmed", "in-review", "dismissed", "fixed"] as const, { description: "Finding status" })),
	// Filters
	severityFilter: Type.Optional(Type.String({ description: "Filter by severity" })),
	statusFilter: Type.Optional(Type.String({ description: "Filter by status" })),
	typeFilter: Type.Optional(Type.String({ description: "Filter by type" })),
	// Misc
	message: Type.Optional(Type.String({ description: "Message for log/flag/note" })),
	reason: Type.Optional(Type.String({ description: "Reason for flag" })),
	policyPath: Type.Optional(Type.String({ description: "Path to company policy file (markdown)" })),
	phase: Type.Optional(Type.String({ description: "Phase to set: recon, fuzzing, exploitation, chaining, verification, reporting, done" })),
});

interface FindingsDetails {
	action: string;
	totalFindings: number;
	critical: number;
	high: number;
	medium: number;
	low: number;
	target?: string;
	phase?: string;
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "findings_context",
		label: "Findings Context",
		description: "Central investigation notebook — single source of truth for the audit. Store findings, track phases, log telemetry, suggest exploit chains, check policy compliance. Actions: add, update, delete, get, list, status, suggest, timeline, export, clear, chain-add, set-target, log, flag, note, set-policy, check-policy, phase.",
		parameters: FindingsParams,
		promptSnippet: "Add a finding to the central store with CVSS score, POC, and chain suggestions",
		promptGuidelines: [
			"Use findings_context add after confirming every vulnerability",
			"Use findings_context status for a dashboard view of the audit",
			"Use findings_context suggest to discover exploit chains between findings",
			"Use findings_context check-policy to validate against company security policy",
			"Use findings_context set-target first to scope the investigation",
			"Chain findings with chain-add for compound impact amplification",
			"Log observations with log action — they surface in timeline and status",
		],

		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			const fp = getStorePath(_ctx.cwd);
			const store = readStore(fp);
			const { session, findings, telemetry, flags, phases } = store;

			const applyFilters = (list: Finding[]) => {
				let filtered = [...list];
				if (params.severityFilter) {
					const s = params.severityFilter.split(",").map((x) => x.trim().toLowerCase());
					filtered = filtered.filter((f) => s.includes(f.severity));
				}
				if (params.statusFilter) {
					const s = params.statusFilter.split(",").map((x) => x.trim().toLowerCase());
					filtered = filtered.filter((f) => s.includes(f.status));
				}
				if (params.typeFilter) {
					const t = params.typeFilter.split(",").map((x) => x.trim().toLowerCase());
					filtered = filtered.filter((f) => t.includes(f.type?.toLowerCase()));
				}
				return filtered;
			};

			switch (params.action) {

				case "log": {
					if (!params.message) return { content: [{ type: "text", text: "Error: message required for log." }], details: { action: "log", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
					const entry: TelemetryEntry = {
						id: genId("T"), type: "log", message: params.message,
						endpoint: params.endpoint, severity: params.severity,
						tags: params.tags ? params.tags.split(",").map((s) => s.trim()) : [],
						timestamp: Date.now(),
					};
					telemetry.push(entry);
					if (telemetry.length > 2000) telemetry.splice(0, telemetry.length - 2000);
					writeFileSync(fp, JSON.stringify(store, null, 2));
					return { content: [{ type: "text", text: `[${new Date().toLocaleTimeString()}] Logged: ${params.message.slice(0, 200)}` }], details: { action: "log", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
				}

				case "flag": {
					if (!params.endpoint) return { content: [{ type: "text", text: "Error: endpoint required for flag." }], details: { action: "flag", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
					const existing = flags.find((f) => f.endpoint === params.endpoint);
					if (existing) {
						existing.reason = params.reason || existing.reason;
						existing.count = (existing.count || 1) + 1;
						existing.lastFlagged = Date.now();
					} else {
						flags.push({
							endpoint: params.endpoint, reason: params.reason || "",
							count: 1, firstFlagged: Date.now(), lastFlagged: Date.now(),
							severity: params.severity || "medium",
						});
					}
					writeFileSync(fp, JSON.stringify(store, null, 2));
					return { content: [{ type: "text", text: `Flagged: ${params.endpoint} — ${params.reason || "no reason"}` }], details: { action: "flag", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
				}

				case "note": {
					if (!params.message) return { content: [{ type: "text", text: "Error: message required for note." }], details: { action: "note", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
					telemetry.push({
						id: genId("N"), type: "note", message: params.message,
						tags: [], timestamp: Date.now(),
					});
					writeFileSync(fp, JSON.stringify(store, null, 2));
					return { content: [{ type: "text", text: `[${new Date().toLocaleTimeString()}] Noted: ${params.message.slice(0, 200)}` }], details: { action: "note", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
				}

		case "add": {
			if (!params.title) return { content: [{ type: "text", text: "Error: title required for add." }], details: { action: "add", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
			if (!params.poc) return { content: [{ type: "text", text: "Error: poc (proof of concept) required for add. Include the exact request that reproduces the finding." }], details: { action: "add", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
			if (!params.description) return { content: [{ type: "text", text: "Error: description required for add. Include request/response evidence (status code, response snippet). A finding without evidence is a hallucination." }], details: { action: "add", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
			if (params.cvssScore === undefined) return { content: [{ type: "text", text: "Error: cvssScore required for add. Run cvss_calculator(action=\"base\", ...) first. Never add a finding without a CVSS score." }], details: { action: "add", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
		if (params.cvssVector === undefined) return { content: [{ type: "text", text: "Error: cvssVector required for add. Run cvss_calculator(action=\"base\", ...) first and include the vector string." }], details: { action: "add", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
		if (!params.severity) return { content: [{ type: "text", text: "Error: severity required for add. Derive from CVSS score: 0.0=info, 1.0-3.9=low, 4.0-6.9=medium, 7.0-8.9=high, 9.0-10.0=critical." }], details: { action: "add", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
			if (!params.cvssVector) return { content: [{ type: "text", text: "Error: cvssVector required for add. Run cvss_calculator(action=\"base\", ...) first and include the vector string." }], details: { action: "add", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
			if (!params.severity) return { content: [{ type: "text", text: "Error: severity required for add. Derive from CVSS score: 0.0=info, 1.0-3.9=low, 4.0-6.9=medium, 7.0-8.9=high, 9.0-10.0=critical." }], details: { action: "add", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
			// Validate cvssScore-severity consistency
			const score = params.cvssScore;
			const sev = params.severity;
			const expectedSev = score === 0 ? "info" : score < 4 ? "low" : score < 7 ? "medium" : score < 9 ? "high" : "critical";
			if (sev !== expectedSev) {
				return { content: [{ type: "text", text: `Error: CVSS score ${score} maps to severity "${expectedSev}", but you passed severity="${sev}". Fix the mismatch. Severity must match the CVSS numerical range: 0.0=info, 1.0-3.9=low, 4.0-6.9=medium, 7.0-8.9=high, 9.0-10.0=critical.` }], details: { action: "add", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
			}
			const id = genId("F");
			const autoTags = [params.type, params.severity, ...VULN_TYPES.filter((t) => (params.title + (params.description || "")).toLowerCase().includes(t))].filter(Boolean) as string[];
			const finding: Finding = {
				id, title: params.title, severity: params.severity,
				type: params.type || "unknown", endpoint: params.endpoint || "",
				cwe: params.cwe || "", description: params.description,
				poc: params.poc, evidence: params.evidence || "",
				remediation: params.remediation || "",
				cvssScore: params.cvssScore, cvssVector: params.cvssVector,
				chainWith: params.chainWith ? params.chainWith.split(",").map((s) => s.trim()).filter(Boolean) : [],
				tags: [...new Set([...autoTags, ...(params.tags ? params.tags.split(",").map((s) => s.trim()) : [])])],
				timestamp: Date.now(), status: params.status || "open",
			};
			findings.push(finding);
			if (params.severity === "critical" || params.severity === "high") {
				session.notes += `[!] ${params.severity}: ${params.title}\n`;
			}
			writeFileSync(fp, JSON.stringify(store, null, 2));
			return {
				content: [{ type: "text", text: `Added ${id}: ${params.title} [${params.severity}]${params.cvssScore ? ` CVSS:${params.cvssScore}` : ""}${params.endpoint ? `\nEndpoint: ${params.endpoint}` : ""}\n${findings.length} total findings` }],
				details: { action: "add", totalFindings: findings.length, critical: findings.filter(f => f.severity === "critical").length, high: findings.filter(f => f.severity === "high").length, medium: findings.filter(f => f.severity === "medium").length, low: findings.filter(f => f.severity === "low").length, target: session.target } as FindingsDetails,
			};
		}

		case "update": {
			const idx = findings.findIndex((f) => f.id === params.findingId);
			if (idx === -1) return { content: [{ type: "text", text: `No finding with id ${params.findingId}` }], details: { action: "update", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
			const f = findings[idx];
			const updatable = ["title", "severity", "type", "endpoint", "cwe", "description", "poc", "evidence", "remediation", "status"] as const;
			let changed = false;
			for (const k of updatable) {
				const val = params[k];
				if (val !== undefined) { f[k] = val; changed = true; }
			}
			if (params.cvssScore) { f.cvssScore = params.cvssScore; changed = true; }
			if (params.cvssVector) { f.cvssVector = params.cvssVector; changed = true; }
			// Auto-correct severity from CVSS score if score was updated
			if (params.cvssScore) {
				const expectedSev = params.cvssScore === 0 ? "info" : params.cvssScore < 4 ? "low" : params.cvssScore < 7 ? "medium" : params.cvssScore < 9 ? "high" : "critical";
				if (params.severity && params.severity !== expectedSev) {
					return { content: [{ type: "text", text: `Error: CVSS score ${params.cvssScore} maps to severity "${expectedSev}", but you passed severity="${params.severity}". Fix the mismatch before updating.` }], details: { action: "update", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
				}
				if (!params.severity) { f.severity = expectedSev; changed = true; }
			}
			if (params.tags) { f.tags = [...new Set([...(f.tags || []), ...params.tags.split(",").map((s) => s.trim())])]; changed = true; }
			if (params.chainWith) { f.chainWith = [...new Set([...(f.chainWith || []), ...params.chainWith.split(",").map((s) => s.trim()).filter(Boolean)])]; changed = true; }
			if (!changed) return { content: [{ type: "text", text: `No-op: update called for ${params.findingId} with no new data. Use findings_context(action="get", findingId="${params.findingId}") to see current state, or provide at least one field to update.` }], details: { action: "update", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
			writeFileSync(fp, JSON.stringify(store, null, 2));
			return { content: [{ type: "text", text: `Updated ${params.findingId}: ${f.title} [${f.severity}]` }], details: { action: "update", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
		}

				case "delete": {
					const before = findings.length;
					const removed = findings.filter((f) => f.id === params.findingId);
					store.findings = findings.filter((f) => f.id !== params.findingId);
					if (store.findings.length === before) return { content: [{ type: "text", text: `No finding ${params.findingId}` }], details: { action: "delete", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
					writeFileSync(fp, JSON.stringify(store, null, 2));
					return { content: [{ type: "text", text: `Deleted ${params.findingId}: ${removed[0]?.title || params.findingId}` }], details: { action: "delete", totalFindings: store.findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
				}

				case "get": {
					const f = findings.find((f) => f.id === params.findingId);
					if (!f) return { content: [{ type: "text", text: `No finding ${params.findingId}` }], details: { action: "get", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
					const chainNames = f.chainWith.map((cid) => findings.find((x) => x.id === cid)).filter(Boolean).map((x) => x!.title);
					const out = [
						`${f.id} | ${f.title}`,
						`  Severity: ${f.severity.toUpperCase()} | CVSS: ${f.cvssScore} | Status: ${f.status}`,
						f.cvssVector ? `  Vector: ${f.cvssVector}` : "",
						f.endpoint ? `  Endpoint: ${f.endpoint}` : "",
						f.type ? `  Type: ${f.type}${f.cwe ? ` | CWE: ${f.cwe}` : ""}` : "",
						f.tags?.length ? `  Tags: ${f.tags.join(", ")}` : "",
						chainNames.length ? `  Chains with: ${chainNames.join(" → ")}` : "",
						f.policyCheck ? `  Policy: ${f.policyCheck}` : "",
						f.description ? `\n  Description: ${f.description}` : "",
						f.poc ? `\n  PoC: ${f.poc.slice(0, 500)}` : "",
						f.evidence ? `\n  Evidence: ${f.evidence.slice(0, 500)}` : "",
						f.remediation ? `\n  Fix: ${f.remediation}` : "",
					].filter(Boolean).join("\n");
					return { content: [{ type: "text", text: out }], details: { action: "get", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
				}

				case "list": {
					const filtered = applyFilters(findings);
					filtered.sort(cmpSev);
					if (!filtered.length) return { content: [{ type: "text", text: "No findings matching filters." }], details: { action: "list", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
					const grouped: Record<string, Finding[]> = {};
					for (const f of filtered) {
						const s = f.severity || "info";
						(grouped[s] ||= []).push(f);
					}
					const sevs = ["critical", "high", "medium", "low", "info"].filter((s) => grouped[s]?.length);
					const out = [
						`Findings: ${filtered.length} (${findings.length} total) | Target: ${session.target || "?"} | Phase: ${session.state}`,
						"",
						...sevs.flatMap((sev) => [
							`[${sev.toUpperCase()}] ${grouped[sev].length}:`,
							...grouped[sev].map((f: any) => `  ${f.id}  ${f.cvssScore ? `CVSS:${f.cvssScore}` : "       "}  ${(f.status || "open").padEnd(10)}  ${f.title.slice(0, 60)}`),
							"",
						]),
						`Flags: ${flags.length} | Telemetry: ${telemetry.length} entries`,
					].join("\n");
					return { content: [{ type: "text", text: out }], details: { action: "list", totalFindings: findings.length, critical: findings.filter(f => f.severity === "critical").length, high: findings.filter(f => f.severity === "high").length, medium: findings.filter(f => f.severity === "medium").length, low: findings.filter(f => f.severity === "low").length, target: session.target } as FindingsDetails };
				}

				case "status": {
					const bySev: Record<string, number> = {};
					for (const f of findings) bySev[f.severity] = (bySev[f.severity] || 0) + 1;
					const statusIcon: Record<string, string> = { planning: "○", recon: "◎", fuzzing: "◉", exploitation: "●", chaining: "◆", verification: "◊", reporting: "▶", done: "■" };
					const sevLine = ["critical", "high", "medium", "low", "info"].filter((s) => bySev[s]).map((s) => `${s}:${bySev[s]}`).join(" | ") || "no findings";
					const flagged = flags.filter((f) => f.count >= 2);
					const phaseCount = Object.entries(phases).filter(([, v]) => v.complete).length;
					const sug = getSuggestions(findings);
					const out = [
						`┌─ Audit Status ────────────────────────────────────`,
						`│ ${statusIcon[session.state] || "○"} ${session.target || "No target"}`,
						`│ Phase: ${session.state} (${phaseCount}/${Object.keys(phases).length} complete)`,
						`│ Findings: ${findings.length} → ${sevLine}`,
						`│ Flags: ${flags.length}${flagged.length ? ` (${flagged.length} high-signal)` : ""}`,
						`│ Telemetry: ${telemetry.length} observations`,
						"│",
						...Object.entries(phases).map(([k, v]) => `│ ${v.complete ? "✓" : "○"} ${k}: ${v.count} findings`),
						sug.length > 0 ? ["│", "│ Chain suggestions:", ...sug.slice(0, 5).map((s) => `│  ${s}`)] : [],
						store.policyPath ? `│ Policy: ${store.policyPath}` : "│ Policy: not configured",
						"└───────────────────────────────────────────────────",
					].flat().join("\n");
					return { content: [{ type: "text", text: out }], details: { action: "status", totalFindings: findings.length, critical: bySev["critical"] || 0, high: bySev["high"] || 0, medium: bySev["medium"] || 0, low: bySev["low"] || 0, target: session.target, phase: session.state } as FindingsDetails };
				}

				case "suggest": {
					const sug = getSuggestions(findings);
					if (!sug.length) return { content: [{ type: "text", text: `No chain suggestions yet (need ≥2 different vuln types). Chain starters: open-redirect, xss, ssrf, idor, race-condition, csrf, cache-poison, sqli` }], details: { action: "suggest", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
					const out = [`Chain suggestions (${findings.length} findings):`, ...sug.map((s, i) => `  ${i + 1}. ${s}`)].join("\n");
					return { content: [{ type: "text", text: out }], details: { action: "suggest", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
				}

				case "timeline": {
					const events: any[] = [
						{ t: session.startTime, d: `Started: ${session.target || "?"}`, type: "session" },
						...findings.map((f) => ({ t: f.timestamp, d: `[${f.severity}] ${f.title}`, type: "finding" })),
						...telemetry.map((t) => ({ t: t.timestamp || Date.now(), d: t.message, type: t.type })),
						...flags.map((f) => ({ t: f.lastFlagged || f.firstFlagged, d: `Flag: ${f.endpoint}`, type: "flag" })),
					].sort((a, b) => a.t - b.t);
					const labels: Record<string, string> = { finding: "[F]", flag: "[!]", session: " # ", telemetry: " · ", log: "  ", note: "  " };
					const out = events.slice(-40).map((e) => `${labels[e.type] || " · "} ${new Date(e.t).toLocaleTimeString()}  ${e.d.slice(0, 90)}`).join("\n");
					return { content: [{ type: "text", text: out || "No events yet." }], details: { action: "timeline", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
				}

				case "export": {
					return { content: [{ type: "text", text: JSON.stringify(store, null, 2) }], details: { action: "export", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
				}

				case "clear": {
					const fresh = JSON.parse(JSON.stringify(INITIAL_STORE)) as FindingsStore;
					fresh.session.target = session.target;
					fresh.policyPath = store.policyPath;
					Object.assign(store, fresh);
					writeFileSync(fp, JSON.stringify(store, null, 2));
					return { content: [{ type: "text", text: `Cleared findings/telemetry/flags. Target: ${session.target || "(not set)"}` }], details: { action: "clear", totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
				}

				case "chain-add": {
					const f = findings.find((f) => f.id === params.findingId);
					if (!f) return { content: [{ type: "text", text: `Finding ${params.findingId} not found.` }], details: { action: "chain-add", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
					const ids = params.chainWith ? params.chainWith.split(",").map((s) => s.trim()).filter(Boolean) : [];
					for (const cid of ids) { if (!f.chainWith.includes(cid)) f.chainWith.push(cid); }
					writeFileSync(fp, JSON.stringify(store, null, 2));
					const chained = f.chainWith.map((cid) => findings.find((x) => x.id === cid)).filter(Boolean).map((x) => x!.title);
					return { content: [{ type: "text", text: `${f.title}\n  → ${chained.join("\n  → ") || "(no chains)"}` }], details: { action: "chain-add", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
				}

			case "set-target": {
				const newTarget = params.title || params.endpoint || params.message || session.target;
				const isReset = newTarget !== session.target;
				session.target = newTarget;
				if (isReset) {
					session.startTime = Date.now();
					session.state = "recon";
				}
				writeFileSync(fp, JSON.stringify(store, null, 2));
				return { content: [{ type: "text", text: `Target set: ${session.target}\nPhase: ${session.state}${isReset ? " (reset)" : " (unchanged)"}\nPolicy check: ${store.policyPath ? "enabled" : "not configured — use set-policy"}` }], details: { action: "set-target", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0, target: session.target } as FindingsDetails };
			}

		case "phase": {
			const order = ["recon", "fuzzing", "exploitation", "chaining", "verification", "reporting", "done"];
			const idx = order.indexOf(session.state);
			if (params.phase && order.includes(params.phase)) {
				// Mark current phase complete before jumping
				if (phases[session.state]) {
					phases[session.state].complete = true;
					phases[session.state].count = findings.filter((f) => f.severity === "critical" || f.severity === "high").length;
				}
				session.state = params.phase;
			} else if (idx < order.length - 1) {
				if (phases[session.state]) {
					phases[session.state].complete = true;
					phases[session.state].count = findings.filter((f) => f.severity === "critical" || f.severity === "high").length;
				}
				session.state = order[idx + 1];
			}
			writeFileSync(fp, JSON.stringify(store, null, 2));
			return { content: [{ type: "text", text: `Phase advanced to: ${session.state}` }], details: { action: "phase", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0, phase: session.state } as FindingsDetails };
		}

				case "set-policy": {
					const policyPath = params.policyPath || params.message || "";
					if (!policyPath) return { content: [{ type: "text", text: "Error: policyPath required." }], details: { action: "set-policy", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
					store.policyPath = policyPath;
					writeFileSync(fp, JSON.stringify(store, null, 2));
					return { content: [{ type: "text", text: `Policy set: ${policyPath}\nFindings will be checked against this policy on add and check-policy.` }], details: { action: "set-policy", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
				}

				case "check-policy": {
					if (!store.policyPath) return { content: [{ type: "text", text: "No policy configured. Use set-policy first." }], details: { action: "check-policy", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
					let policy: string;
					try {
						policy = readFileSync(store.policyPath, "utf-8").toLowerCase();
					} catch {
						return { content: [{ type: "text", text: `Could not read policy at ${store.policyPath}` }], details: { action: "check-policy", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
					}

					// Word-boundary matching to avoid false positives (e.g. "critical" matching inside "non-critical")
					const hasWord = (text: string, word: string): boolean => {
						const re = new RegExp(`\\b${word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
						return re.test(text);
					};

					const all = applyFilters(findings);
					const results: string[] = [];
					for (const f of all) {
						const checks: string[] = [];
						if (f.severity === "critical" && hasWord(policy, "critical")) checks.push("critical findings mandatory");
						if (f.severity === "high" && hasWord(policy, "high")) checks.push("high severity review");
						if (f.type === "sqli" && (hasWord(policy, "sqli") || hasWord(policy, "sql injection") || hasWord(policy, "injection"))) checks.push("SQLi covered by injection policy");
						if (f.type === "xss" && (hasWord(policy, "xss") || hasWord(policy, "cross-site scripting"))) checks.push("XSS covered by policy");
						if (f.type === "ssrf" && hasWord(policy, "ssrf")) checks.push("SSRF covered by policy");
						if (f.type === "idor" && (hasWord(policy, "idor") || hasWord(policy, "broken access control"))) checks.push("IDOR covered by access control policy");
						if (f.type === "rce" && (hasWord(policy, "rce") || hasWord(policy, "remote code execution"))) checks.push("RCE covered by policy");
						if (f.cwe && hasWord(policy, f.cwe.toLowerCase())) checks.push(`CWE ${f.cwe} referenced`);
						if (f.tags?.some((t) => hasWord(policy, t.toLowerCase()))) checks.push("tag referenced in policy");
						if (f.endpoint && policy.split("\n").some((l) => l.includes(f.endpoint.toLowerCase()))) checks.push("endpoint referenced in policy");

						if (checks.length > 0) {
							f.policyCheck = checks.join("; ");
							results.push(`✓ ${f.id} ${f.title} — ${checks.join(", ")}`);
						} else {
							f.policyCheck = "no policy match — may be out of scope";
							results.push(`? ${f.id} ${f.title} — ${f.policyCheck}`);
						}
					}
					writeFileSync(fp, JSON.stringify(store, null, 2));
					return {
						content: [{ type: "text", text: `Policy check against ${store.policyPath}:\n\n${results.join("\n")}\n\n${results.length} findings checked.` }],
						details: { action: "check-policy", totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails,
					};
				}

				default:
					return { content: [{ type: "text", text: `Unknown action: ${params.action}` }], details: { action: params.action, totalFindings: findings.length, critical: 0, high: 0, medium: 0, low: 0 } as FindingsDetails };
			}
		},

		renderCall(args, theme, _context) {
			const action = (args.action as string) || "?";
			let text = theme.fg("toolTitle", theme.bold("findings ")) + theme.fg("accent", action);
			if (args.title) text += ` ${theme.fg("dim", `"${(args.title as string).slice(0, 30)}"`)}`;
			if (args.severity) text += ` ${theme.fg("warning", (args.severity as string).toUpperCase())}`;
			return new Text(text, 0, 0);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as FindingsDetails | undefined;
			if (!details) {
				const t = result.content[0];
				return new Text(t?.type === "text" ? t.text.slice(0, 100) : "", 0, 0);
			}
			const summary = [
				details.critical ? theme.fg("error", `${details.critical}C`) : null,
				details.high ? theme.fg("warning", `${details.high}H`) : null,
				details.medium ? theme.fg("accent", `${details.medium}M`) : null,
				details.low ? theme.fg("dim", `${details.low}L`) : null,
			].filter(Boolean).join(" ");
			return new Text(
				theme.fg("success", `✓ ${details.totalFindings} findings `) + summary +
				(details.target ? ` ${theme.fg("dim", `@${details.target.slice(0, 25)}`)}` : ""),
				0, 0,
			);
		},
	});
}
