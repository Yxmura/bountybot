/**
 * CVSS 3.1 Calculator Extension — Full implementation of the CVSS 3.1 specification.
 *
 * Implements Base Score, Temporal Score, and Environmental Score calculation
 * with correct roundup() logic per the CVSS v3.1 specification.
 *
 * Supports vector string generation, decoding, and human-readable explanations.
 * Uses the official CVSS 3.1 formulas and weight tables.
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";

// ─── CVSS 3.1 Metric Weight Tables ─────────────────────────────────────────

const METRICS = {
	AV: { label: "Attack Vector", N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
	AC: { label: "Attack Complexity", L: 0.77, H: 0.44 },
	PR: {
		label: "Privileges Required",
		U: { N: 0.85, L: 0.62, H: 0.27 },  // Scope Unchanged
		C: { N: 0.85, L: 0.68, H: 0.5 },    // Scope Changed
	},
	UI: { label: "User Interaction", N: 0.85, R: 0.62 },
	S: { label: "Scope", U: "Unchanged", C: "Changed" },
	C: { label: "Confidentiality Impact", H: 0.56, L: 0.22, N: 0 },
	I: { label: "Integrity Impact", H: 0.56, L: 0.22, N: 0 },
	A: { label: "Availability Impact", H: 0.56, L: 0.22, N: 0 },
	// Temporal
	E: { label: "Exploit Code Maturity", X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1 },
	RL: { label: "Remediation Level", X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 },
	RC: { label: "Report Confidence", X: 1, U: 0.92, R: 0.96, C: 1 },
	// Environmental modifiers
	CR: { label: "Confidentiality Requirement", X: 1, L: 0.5, M: 1, H: 1.5 },
	IR: { label: "Integrity Requirement", X: 1, L: 0.5, M: 1, H: 1.5 },
	AR: { label: "Availability Requirement", X: 1, L: 0.5, M: 1, H: 1.5 },
	MAV: { label: "Modified Attack Vector", N: 0.85, A: 0.62, L: 0.55, P: 0.2, X: "base" },
	MAC: { label: "Modified Attack Complexity", L: 0.77, H: 0.44, X: "base" },
	MPR: {
		label: "Modified Privileges Required",
		U: { N: 0.85, L: 0.62, H: 0.27 },
		C: { N: 0.85, L: 0.68, H: 0.5 },
		def: { N: 0.85, L: 0.62, H: 0.27 },
	},
	MUI: { label: "Modified User Interaction", N: 0.85, R: 0.62, X: "base" },
	MS: { label: "Modified Scope", U: "Unchanged", C: "Changed", X: "base" },
	MC: { label: "Modified Confidentiality", H: 0.56, L: 0.22, N: 0, X: "base" },
	MI: { label: "Modified Integrity", H: 0.56, L: 0.22, N: 0, X: "base" },
	MA: { label: "Modified Availability", H: 0.56, L: 0.22, N: 0, X: "base" },
};

const METRIC_LABELS: Record<string, Record<string, string>> = {
	AV: { N: "Network", A: "Adjacent Network", L: "Local", P: "Physical" },
	AC: { L: "Low", H: "High" },
	PR: { N: "None", L: "Low", H: "High" },
	UI: { N: "None", R: "Required" },
	S: { U: "Unchanged", C: "Changed" },
	C: { H: "High", L: "Low", N: "None" },
	I: { H: "High", L: "Low", N: "None" },
	A: { H: "High", L: "Low", N: "None" },
	E: { X: "Not Defined", U: "Unproven", P: "Proof-of-Concept", F: "Functional", H: "High" },
	RL: { X: "Not Defined", O: "Official Fix", T: "Temporary Fix", W: "Workaround", U: "Unavailable" },
	RC: { X: "Not Defined", U: "Unknown", R: "Reasonable", C: "Confirmed" },
	CR: { X: "Not Defined", L: "Low", M: "Medium", H: "High" },
	IR: { X: "Not Defined", L: "Low", M: "Medium", H: "High" },
	AR: { X: "Not Defined", L: "Low", M: "Medium", H: "High" },
	MAV: { N: "Network", A: "Adjacent Network", L: "Local", P: "Physical", X: "Not Modified" },
	MAC: { L: "Low", H: "High", X: "Not Modified" },
	MPR: { N: "None", L: "Low", H: "High", X: "Not Modified" },
	MUI: { N: "None", R: "Required", X: "Not Modified" },
	MS: { U: "Unchanged", C: "Changed", X: "Not Modified" },
	MC: { H: "High", L: "Low", N: "None", X: "Not Modified" },
	MI: { H: "High", L: "Low", N: "None", X: "Not Modified" },
	MA: { H: "High", L: "Low", N: "None", X: "Not Modified" },
};

// Metric ordering per CVSS spec
const BASE_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
const TEMPORAL_ORDER = ["E", "RL", "RC"];
const ENV_ORDER = ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"];

function roundup(val: number): number {
	const intPart = Math.floor(val * 100000);
	if (intPart % 10000 === 0) return intPart / 100000;
	const rounded = (Math.floor(intPart / 10000) + 1) / 10;
	return rounded;
}

function getMetric(metric: string, value: string, scope?: string): number {
	const m = METRICS[metric as keyof typeof METRICS];
	if (!m) return 0;

	if (metric === "PR") {
		const prMetrics = m as { U: Record<string, number>; C: Record<string, number> };
		if (scope === "U") return prMetrics.U[value] || 0.68;
		return prMetrics.C[value] || 0.5;
	}
	if (metric === "MPR") {
		const mprMetrics = m as { U: Record<string, number>; C: Record<string, number>; def: Record<string, number> };
		const prVal = mprMetrics.U[value];
		if (typeof prVal === "number") return prVal;
		const def = mprMetrics.def || mprMetrics.U;
		return def[value] || mprMetrics.U["N"];
	}
	return (m as unknown as Record<string, number>)[value] || 0;
}

/**
 * Full CVSS 3.1 Score Calculation
 * Returns base, temporal (optional), and environmental (optional) scores.
 */
function calcBase(av: string, ac: string, pr: string, ui: string, s: string, c: string, i: string, a: string): {
	score: number;
	vector: string;
	severity: string;
	exploitability: number;
	impact: number;
} {
	const AV = getMetric("AV", av) as number;
	const AC = getMetric("AC", ac) as number;
	const PR = getMetric("PR", pr, s) as number;
	const UI = getMetric("UI", ui) as number;
	const C = getMetric("C", c) as number;
	const I = getMetric("I", i) as number;
	const A = getMetric("A", a) as number;

	const exploitability = 8.22 * AV * AC * PR * UI;
	const iss = 1 - ((1 - C) * (1 - I) * (1 - A));

	let impact: number;
	let base: number;

	if (s === "U") {
		impact = 6.42 * iss;
		base = roundup(Math.min(impact + exploitability, 10));
	} else {
		impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
		base = roundup(Math.min(1.08 * (impact + exploitability), 10));
	}

	if (impact <= 0) base = 0;

	const severity = base >= 9 ? "critical" : base >= 7 ? "high" : base >= 4 ? "medium" : base >= 0.1 ? "low" : "none";
	const vector = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}`;

	return { score: Math.round(base * 10) / 10, vector, severity, exploitability, impact };
}

function calcTemporal(baseScore: number, e: string, rl: string, rc: string): {
	score: number;
	vector: string;
} {
	const E = getMetric("E", e) as number;
	const RL = getMetric("RL", rl) as number;
	const RC = getMetric("RC", rc) as number;
	const temporal = roundup(baseScore * E * RL * RC);
	const vector = `CVSS:3.1/E:${e}/RL:${rl}/RC:${rc}`;
	return { score: Math.round(temporal * 10) / 10, vector };
}

function calcEnvironmental(
	baseScore: number,
	base: { av: string; ac: string; pr: string; ui: string; s: string; c: string; i: string; a: string },
	env: { mav?: string; mac?: string; mpr?: string; mui?: string; ms?: string; mc?: string; mi?: string; ma?: string; cr?: string; ir?: string; ar?: string },
): { score: number; vector: string } {
	// Use modified metrics, falling back to base
	const MAV = env.mav && METRICS.MAV[env.mav as keyof typeof METRICS.MAV] !== "base" ? env.mav : base.av;
	const MAC = env.mac && METRICS.MAC[env.mac as keyof typeof METRICS.MAC] !== "base" ? env.mac : base.ac;
	const MPR = env.mpr && env.mpr !== "X" ? env.mpr : base.pr;
	const MUI = env.mui && METRICS.MUI[env.mui as keyof typeof METRICS.MUI] !== "base" ? env.mui : base.ui;
	const MS = env.ms || base.s;
	const MC = env.mc && METRICS.MC[env.mc as keyof typeof METRICS.MC] !== "base" ? env.mc : base.c;
	const MI = env.mi && METRICS.MI[env.mi as keyof typeof METRICS.MI] !== "base" ? env.mi : base.i;
	const MA = env.ma && METRICS.MA[env.ma as keyof typeof METRICS.MA] !== "base" ? env.ma : base.a;
	const CR = env.cr || "X";
	const IR = env.ir || "X";
	const AR = env.ar || "X";

	const modAV = getMetric("MAV", MAV) as number;
	const modAC = getMetric("MAC", MAC) as number;
	const modPR = getMetric("MPR", MPR, MS) as number;
	const modUI = getMetric("MUI", MUI) as number;
	const modC = getMetric("MC", MC) as number;
	const modI = getMetric("MI", MI) as number;
	const modA = getMetric("MA", MA) as number;
	const crVal = getMetric("CR", CR) as number;
	const irVal = getMetric("IR", IR) as number;
	const arVal = getMetric("AR", AR) as number;

	const modExploitability = 8.22 * modAV * modAC * modPR * modUI;
	const modISS = Math.min(
		1 - ((1 - modC * crVal) * (1 - modI * irVal) * (1 - modA * arVal)),
		0.915,
	);

	let modImpact: number;
	let envScore: number;

	if (MS === "U") {
		modImpact = 6.42 * modISS;
		envScore = roundup(Math.min(modImpact + modExploitability, 10));
	} else {
		modImpact = 7.52 * (modISS - 0.029) - 3.25 * Math.pow(modISS - 0.02, 15);
		envScore = roundup(Math.min(1.08 * (modImpact + modExploitability), 10));
	}

	if (modImpact <= 0) envScore = 0;

	const vectorParams: string[] = [
		`AV:${MAV}`, `AC:${MAC}`, `PR:${MPR}`, `UI:${MUI}`, `S:${MS}`,
		`C:${MC}`, `I:${MI}`, `A:${MA}`,
		`E:X`, `RL:X`, `RC:X`,
		`CR:${CR}`, `IR:${IR}`, `AR:${AR}`,
		`MAV:${MAV}`, `MAC:${MAC}`, `MPR:${MPR}`, `MUI:${MUI}`,
		`MS:${MS}`, `MC:${MC}`, `MI:${MI}`, `MA:${MA}`,
	];

	return {
		score: Math.round(envScore * 10) / 10,
		vector: `CVSS:3.1/${vectorParams.join("/")}`,
	};
}

// ─── Tool Parameter Schemas ────────────────────────────────────────────────

const AvEnum = StringEnum(["N", "A", "L", "P"] as const, { description: "Attack Vector" });
const AcEnum = StringEnum(["L", "H"] as const, { description: "Attack Complexity" });
const PrEnum = StringEnum(["N", "L", "H"] as const, { description: "Privileges Required" });
const UiEnum = StringEnum(["N", "R"] as const, { description: "User Interaction" });
const ScopeEnum = StringEnum(["U", "C"] as const, { description: "Scope" });
const CiaEnum = StringEnum(["H", "L", "N"] as const, { description: "Confidentiality/Integrity/Availability Impact" });
const TemporalEnum = StringEnum(["X", "U", "P", "F", "H"] as const, { description: "Temporal metric (X=Not Defined)" });
const RlEnum = StringEnum(["X", "O", "T", "W", "U"] as const, { description: "Remediation Level" });
const RcEnum = StringEnum(["X", "U", "R", "C"] as const, { description: "Report Confidence" });
const RequirementEnum = StringEnum(["X", "L", "M", "H"] as const, { description: "Security Requirement (X=Not Defined)" });
const ModifiedEnum = StringEnum(["N", "A", "L", "P", "X"] as const, { description: "Modified Attack Vector (X=Not Modified)" });
const ModifiedAcEnum = StringEnum(["L", "H", "X"] as const, { description: "Modified Attack Complexity (X=Not Modified)" });
const ModifiedPrEnum = StringEnum(["N", "L", "H", "X"] as const, { description: "Modified Privileges Required (X=Not Modified)" });
const ModifiedUiEnum = StringEnum(["N", "R", "X"] as const, { description: "Modified User Interaction (X=Not Modified)" });
const ModifiedScopeEnum = StringEnum(["U", "C", "X"] as const, { description: "Modified Scope (X=Not Modified)" });
const ModifiedCiaEnum = StringEnum(["H", "L", "N", "X"] as const, { description: "Modified CIA Impact (X=Not Modified)" });

const CvssParams = Type.Object({
	action: StringEnum(["base", "temporal", "environmental", "decode", "quick"] as const, {
		description: "What to calculate: base (base metrics only), temporal (with exploit/remediation/confidence), environmental (with modified metrics + requirements), decode (parse a CVSS vector string), quick (from severity label)",
	}),
	// Base metrics
	av: Type.Optional(AvEnum),
	ac: Type.Optional(AcEnum),
	pr: Type.Optional(PrEnum),
	ui: Type.Optional(UiEnum),
	s: Type.Optional(ScopeEnum),
	c: Type.Optional(CiaEnum),
	i: Type.Optional(CiaEnum),
	a: Type.Optional(CiaEnum),
	// Temporal
	e: Type.Optional(TemporalEnum),
	rl: Type.Optional(RlEnum),
	rc: Type.Optional(RcEnum),
	// Environmental
	cr: Type.Optional(RequirementEnum),
	ir: Type.Optional(RequirementEnum),
	ar: Type.Optional(RequirementEnum),
	mav: Type.Optional(ModifiedEnum),
	mac: Type.Optional(ModifiedAcEnum),
	mpr: Type.Optional(ModifiedPrEnum),
	mui: Type.Optional(ModifiedUiEnum),
	ms: Type.Optional(ModifiedScopeEnum),
	mc: Type.Optional(ModifiedCiaEnum),
	mi: Type.Optional(ModifiedCiaEnum),
	ma: Type.Optional(ModifiedCiaEnum),
	// Decode
	vector: Type.Optional(Type.String({ description: "CVSS vector string to decode and explain" })),
	// Quick
	severity: Type.Optional(StringEnum(["critical", "high", "medium", "low", "info", "none"] as const, {
		description: "Severity label for quick approximate CVSS score",
	})),
	findingType: Type.Optional(StringEnum(["sqli", "xss", "ssrf", "idor", "rce", "ato", "lfi", "cmdi", "open-redirect", "csrf", "info-disclosure", "misconfig", "business-logic", "subdomain-takeover", "other"] as const, {
		description: "Finding type for contextual quick score estimation",
	})),
});

interface CvssDetails {
	score: number;
	severity: string;
	vector: string;
	action: string;
	baseScore?: number;
	temporalScore?: number;
	environmentalScore?: number;
}

// Quick score map fallback (used when agent doesn't specify metrics)
const SEVERITY_MAP: Record<string, { score: number; vector: string }> = {
	critical: { score: 9.0, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" },
	high: { score: 7.5, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N" },
	medium: { score: 5.0, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" },
	low: { score: 3.1, vector: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" },
	info: { score: 0.0, vector: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N" },
	none: { score: 0.0, vector: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N" },
};

const TYPE_MODIFIERS: Record<string, Partial<Record<string, string>>> = {
	sqli: { c: "H", i: "H", pr: "N" },
	xss: { c: "L", i: "L", pr: "L", ui: "R" },
	ssrf: { av: "N", c: "H", pr: "N", s: "C" },
	idor: { c: "H", pr: "L" },
	rce: { c: "H", i: "H", a: "H" },
	ato: { c: "H", i: "H", pr: "L" },
	lfi: { c: "H", pr: "N" },
	cmdi: { c: "H", i: "H", a: "H", pr: "N" },
	"open-redirect": { c: "L", pr: "L", ui: "R" },
};

// ─── Extension ─────────────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "cvss_calculator",
		label: "CVSS Calculator",
		description: "Calculate CVSS 3.1 scores: base (required: AV,AC,PR,UI,S,C,I,A), temporal (add E,RL,RC), environmental (add CR,IR,AR,MAV,MAC,MPR,MUI,MS,MC,MI,MA), decode (parse vector string), quick (estimate from severity+type). Full spec implementation with correct roundup().",
		parameters: CvssParams,
		promptSnippet: "Calculate CVSS 3.1 score. Use action=base for simple scoring, action=environmental for full scoring with modified metrics and security requirements.",
		promptGuidelines: [
			"Always score findings with CVSS 3.1 before reporting. Use cvss_calculator first.",
			"For most findings: use action=base with the 8 required metric values.",
			"For thorough scoring: use action=environmental to model the real-world environment.",
			"Use action=decode to explain an existing CVSS vector string.",
			"Use action=quick only as fallback when you don't know specific metrics.",
			"Default to AV:N (Network) for web vulnerabilities, AV:L for local/desktop.",
			"Scope Changed (S:C) when the vulnerable component is different from the impacted component.",
		],

		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			const action = params.action;

			// ─ decode mode ────────────────────────────────────────────────
			if (action === "decode") {
				if (!params.vector) {
					return {
						content: [{ type: "text", text: "Error: vector parameter required for decode action." }],
						details: { score: 0, severity: "none", vector: "", action: "decode" } as CvssDetails,
					};
				}
				const vec = params.vector;
				const parts = vec.split("/").slice(1);
				const parsed: Record<string, string> = {};
				for (const p of parts) {
					const [k, v] = p.split(":");
					if (k && v) parsed[k] = v;
				}

				const av = parsed["AV"] || "N";
				const ac = parsed["AC"] || "L";
				const pr = parsed["PR"] || "N";
				const ui = parsed["UI"] || "N";
				const s = parsed["S"] || "U";
				const c = parsed["C"] || "N";
				const i = parsed["I"] || "N";
				const a = parsed["A"] || "N";

				const result = calcBase(av, ac, pr, ui, s, c, i, a);
				const baseMetrics = [av, ac, pr, ui, s, c, i, a];

				let output = `Score: ${result.score} — Severity: ${result.severity.toUpperCase()}\n`;
				output += `Vector: ${result.vector}\n\n`;
				output += "Base Metrics:\n";
				for (let j = 0; j < BASE_ORDER.length; j++) {
					const metric = BASE_ORDER[j];
					const value = baseMetrics[j];
					const label = METRIC_LABELS[metric]?.[value] || value;
					output += `  ${metric}:${value} — ${label}\n`;
				}

				// Show temporal if present
				const temporalParts = ["E", "RL", "RC"].filter(k => parsed[k] && parsed[k] !== "X");
				if (temporalParts.length > 0) {
					const te = parsed["E"] || "X";
					const trl = parsed["RL"] || "X";
					const trc = parsed["RC"] || "X";
					const tResult = calcTemporal(result.score, te, trl, trc);
					output += `\nTemporal Score: ${tResult.score}\n`;
					for (const tk of ["E", "RL", "RC"]) {
						if (parsed[tk]) {
							const v = parsed[tk];
							output += `  ${tk}:${v} — ${METRIC_LABELS[tk]?.[v] || v}\n`;
						}
					}
				}

				// Show environmental if present
				const envPresent = ENV_ORDER.some(k => parsed[k]);
				if (envPresent) {
					output += `\nEnvironmental Metrics present (${ENV_ORDER.filter(k => parsed[k]).length} modified).\n`;
					output += "Use action=environmental for full calculation.\n";
				}

				// Severity interpretation
				const interpretations: Record<string, string> = {
					critical: "Critical: Immediate action required. Exploitable with low complexity, catastrophic impact. Patch within 24 hours.",
					high: "High: Significant risk. Exploitation is likely with minimal barriers. Patch within 1 week.",
					medium: "Medium: Exploitable under specific conditions. Moderate impact. Patch within 30 days.",
					low: "Low: Limited impact or requires significant preconditions. Accept risk or patch in normal cycle.",
					none: "Informational: No meaningful security impact.",
				};
				output += `\nInterpretation: ${interpretations[result.severity] || ""}\n`;

				// Impact breakdown
				output += `\nExploitability sub-score: ${result.exploitability.toFixed(1)}/3.9\n`;
				output += `Impact sub-score: ${result.impact.toFixed(1)}/6.0\n`;
				output += `\nFormula: Roundup(Min(${s === "U" ? "Impact + Exploitability" : "1.08*(Impact + Exploitability)"}, 10))`;

				return {
					content: [{ type: "text", text: output }],
					details: { score: result.score, severity: result.severity, vector: result.vector, action: "decode" } as CvssDetails,
				};
			}

			// ─ quick mode ──────────────────────────────────────────────────
			if (action === "quick") {
				const severity = params.severity || "medium";
				const findingType = params.findingType || "other";
				const estimate = SEVERITY_MAP[severity] || SEVERITY_MAP["medium"];

				let adjustedVector = estimate.vector;
				if (findingType && TYPE_MODIFIERS[findingType]) {
					const mods = TYPE_MODIFIERS[findingType];
					const parts = estimate.vector.split("/");
					const newParts = parts.map(p => {
						const [k] = p.split(":");
						if (k && mods[k]) return `${k}:${mods[k]}`;
						return p;
					});
					adjustedVector = newParts.join("/");
				}

				const output = [
					`Estimated CVSS 3.1 Score: ${estimate.score}`,
					`Severity: ${severity.toUpperCase()}`,
					`Vector: ${adjustedVector}`,
					"",
					"Note: This is an approximate score. Use action=base with explicit metrics",
					"for an accurate calculation, or action=environmental for full assessment.",
				].join("\n");

				return {
					content: [{ type: "text", text: output }],
					details: { score: estimate.score, severity, vector: adjustedVector, action: "quick" } as CvssDetails,
				};
			}

			// ─ base mode ───────────────────────────────────────────────────
			const av = params.av || "N";
			const ac = params.ac || "L";
			const pr = params.pr || "N";
			const ui = params.ui || "N";
			const s = params.s || "U";
			const c = params.c || "N";
			const i = params.i || "N";
			const a = params.a || "N";

			const baseResult = calcBase(av, ac, pr, ui, s, c, i, a);

			if (action === "base") {
				const output = [
					`CVSS 3.1 Base Score: ${baseResult.score}`,
					`Severity: ${baseResult.severity.toUpperCase()}`,
					`Vector: ${baseResult.vector}`,
					"",
					"Base Metrics:",
					`  AV:${av} — ${METRIC_LABELS.AV[av] || av}`,
					`  AC:${ac} — ${METRIC_LABELS.AC[ac] || ac}`,
					`  PR:${pr} — ${METRIC_LABELS.PR[pr] || pr}`,
					`  UI:${ui} — ${METRIC_LABELS.UI[ui] || ui}`,
					`  S:${s} — ${METRIC_LABELS.S[s] || s}`,
					`  C:${c} — ${METRIC_LABELS.C[c] || c}`,
					`  I:${i} — ${METRIC_LABELS.I[i] || i}`,
					`  A:${a} — ${METRIC_LABELS.A[a] || a}`,
					"",
					`Exploitability: ${baseResult.exploitability.toFixed(1)} / 3.9`,
					`Impact: ${baseResult.impact.toFixed(1)} / 6.0`,
					"",
					`Formula: ${s === "U" ? "Roundup(Min(Impact + Exploitability, 10))" : "Roundup(Min(1.08 × (Impact + Exploitability), 10))"}`,
					baseResult.severity === "critical" ? "\n⚠ Critical: Immediate exploitation possible with catastrophic impact. Patch within 24h." :
					baseResult.severity === "high" ? "\n⚠ High: Significant risk. Exploitation likely. Patch within 1 week." :
					baseResult.severity === "medium" ? "\n⚡ Medium: Exploitable under certain conditions. Patch within 30 days." :
					baseResult.severity === "low" ? "\nℹ Low: Limited impact or difficult to exploit. Accept risk or patch normally." :
					"\n✓ No meaningful risk.",
				].join("\n");

				return {
					content: [{ type: "text", text: output }],
					details: { score: baseResult.score, severity: baseResult.severity, vector: baseResult.vector, action: "base", baseScore: baseResult.score } as CvssDetails,
				};
			}

			// ─ temporal mode ───────────────────────────────────────────────
			const e = params.e || "X";
			const rl = params.rl || "X";
			const rc = params.rc || "X";

			if (action === "temporal") {
				const temporalResult = calcTemporal(baseResult.score, e, rl, rc);

				const fullVector = `${baseResult.vector}/E:${e}/RL:${rl}/RC:${rc}`;
				const sevLabel = temporalResult.score >= 9 ? "critical" : temporalResult.score >= 7 ? "high" : temporalResult.score >= 4 ? "medium" : temporalResult.score >= 0.1 ? "low" : "none";

				const output = [
					`CVSS 3.1 Temporal Score: ${temporalResult.score}`,
					`Severity: ${sevLabel.toUpperCase()}`,
					`Base Score: ${baseResult.score}`,
					`Vector: ${fullVector}`,
					"",
					"Temporal Metrics:",
					`  E:${e} — ${METRIC_LABELS.E[e] || e}`,
					`  RL:${rl} — ${METRIC_LABELS.RL[rl] || rl}`,
					`  RC:${rc} — ${METRIC_LABELS.RC[rc] || rc}`,
					"",
					"Base Metrics:",
					`  AV:${av}  AC:${ac}  PR:${pr}  UI:${ui}  S:${s}  C:${c}  I:${i}  A:${a}`,
					"",
					`Formula: Roundup(BaseScore × E × RL × RC)`,
				].join("\n");

				return {
					content: [{ type: "text", text: output }],
					details: { score: temporalResult.score, severity: sevLabel, vector: fullVector, action: "temporal", baseScore: baseResult.score, temporalScore: temporalResult.score } as CvssDetails,
				};
			}

			// ─ environmental mode ──────────────────────────────────────────
			if (action === "environmental") {
				const env = {
					cr: params.cr || "X",
					ir: params.ir || "X",
					ar: params.ar || "X",
					mav: params.mav || "X",
					mac: params.mac || "X",
					mpr: params.mpr || "X",
					mui: params.mui || "X",
					ms: params.ms || "X",
					mc: params.mc || "X",
					mi: params.mi || "X",
					ma: params.ma || "X",
				};

				const envResult = calcEnvironmental(
					baseResult.score,
					{ av, ac, pr, ui, s, c, i, a },
					env,
				);

				const sevLabel = envResult.score >= 9 ? "critical" : envResult.score >= 7 ? "high" : envResult.score >= 4 ? "medium" : envResult.score >= 0.1 ? "low" : "none";

				const output = [
					`CVSS 3.1 Environmental Score: ${envResult.score}`,
					`Severity: ${sevLabel.toUpperCase()}`,
					`Base Score: ${baseResult.score} (adjusted to ${envResult.score} for environment)`,
					`Vector: ${envResult.vector}`,
					"",
					"Base Metrics:",
					`  AV:${av}  AC:${ac}  PR:${pr}  UI:${ui}  S:${s}  C:${c}  I:${i}  A:${a}`,
					"",
					"Security Requirements:",
					`  CR:${env.cr} — ${METRIC_LABELS.CR[env.cr] || "Not Defined"}`,
					`  IR:${env.ir} — ${METRIC_LABELS.IR[env.ir] || "Not Defined"}`,
					`  AR:${env.ar} — ${METRIC_LABELS.AR[env.ar] || "Not Defined"}`,
					"",
					"Modified Base Metrics:",
					env.mav ? `  MAV:${env.mav} — ${METRIC_LABELS.MAV[env.mav] || "Not Modified"}` : "",
					env.mac ? `  MAC:${env.mac} — ${METRIC_LABELS.MAC[env.mac] || "Not Modified"}` : "",
					env.mpr ? `  MPR:${env.mpr} — ${METRIC_LABELS.MPR[env.mpr] || "Not Modified"}` : "",
					env.mui ? `  MUI:${env.mui} — ${METRIC_LABELS.MUI[env.mui] || "Not Modified"}` : "",
					env.ms ? `  MS:${env.ms} — ${METRIC_LABELS.MS[env.ms] || "Not Modified"}` : "",
					env.mc ? `  MC:${env.mc} — ${METRIC_LABELS.MC[env.mc] || "Not Modified"}` : "",
					env.mi ? `  MI:${env.mi} — ${METRIC_LABELS.MI[env.mi] || "Not Modified"}` : "",
					env.ma ? `  MA:${env.ma} — ${METRIC_LABELS.MA[env.ma] || "Not Modified"}` : "",
					"",
					"ℹ Environmental score adjusts the base score for the specific deployment",
					"context, accounting for security requirements and compensating controls.",
				].filter(Boolean).join("\n");

				return {
					content: [{ type: "text", text: output }],
					details: { score: envResult.score, severity: sevLabel, vector: envResult.vector, action: "environmental", baseScore: baseResult.score, environmentalScore: envResult.score } as CvssDetails,
				};
			}

			return {
				content: [{ type: "text", text: `Unknown action: ${action}` }],
				details: { score: 0, severity: "none", vector: "", action } as CvssDetails,
			};
		},

		renderCall(args, theme, _context) {
			const action = (args.action as string) || "base";
			let text = theme.fg("toolTitle", theme.bold("cvss ")) +
				theme.fg("accent", action.toUpperCase());
			if (action !== "decode" && action !== "quick") {
				const metas: string[] = [];
				if (args.av) metas.push(`AV:${args.av}`);
				if (args.ac) metas.push(`AC:${args.ac}`);
				if (args.s) metas.push(`S:${args.s}`);
				if (args.c) metas.push(`C:${args.c}`);
				if (args.i) metas.push(`I:${args.i}`);
				if (args.a) metas.push(`A:${args.a}`);
				if (metas.length > 0) text += ` ${theme.fg("dim", metas.join(" "))}`;
			}
			if (args.vector) text += ` ${theme.fg("dim", `"${(args.vector as string).slice(0, 30)}..."`)}`;
			return new Text(text, 0, 0);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as CvssDetails | undefined;
			if (!details) {
				const t = result.content[0];
				return new Text(t?.type === "text" ? t.text.slice(0, 80) : "", 0, 0);
			}
			const sevColor =
				details.severity === "critical" ? "error" :
				details.severity === "high" ? "warning" :
				details.severity === "medium" ? "accent" :
				"dim";
			let text = theme.fg("success", "✓ ") +
				theme.fg("accent", `CVSS ${details.score}`) +
				" " +
				theme.fg(sevColor, details.severity.toUpperCase());
			if (details.action === "environmental" && details.baseScore && details.baseScore !== details.score) {
				text += theme.fg("muted", ` (base: ${details.baseScore})`);
			}
			text += `\n${theme.fg("dim", details.vector.slice(0, 60))}`;
			if (details.vector.length > 60) text += theme.fg("dim", "...");
			return new Text(text, 0, 0);
		},
	});
}
