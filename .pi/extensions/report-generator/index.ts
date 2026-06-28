/**
 * Report Generator Extension — Platform-formatted vulnerability reports.
 *
 * Generates structured vulnerability reports formatted for specific
 * bug bounty platforms: Intigriti, HackerOne, and Bugcrowd.
 *
 * Output format is Markdown that can be copy-pasted into each platform's
 * submission form, or exported as files.
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const PlatformEnum = StringEnum(["intigriti", "hackerone", "bugcrowd"] as const, {
	description: "Bug bounty platform for report format",
});

const SeverityEnum = StringEnum(["critical", "high", "medium", "low", "informational"] as const, {
	description: "Vulnerability severity level",
});

const CategoryKeyword = StringEnum([
	"idor",
	"xss",
	"sqli",
	"ssrf",
	"csrf",
	"auth-bypass",
	"info-disclosure",
	"rce",
	"lfi-rfi",
	"open-redirect",
	"business-logic",
	"misconfiguration",
	"rate-limit",
	"subdomain-takeover",
	"other",
] as const);

const ReportParams = Type.Object({
	action: StringEnum(["generate", "template", "export"] as const),
	platform: PlatformEnum,
	title: Type.Optional(Type.String({ description: "Vulnerability title (for generate)" })),
	severity: Type.Optional(SeverityEnum),
	category: Type.Optional(CategoryKeyword),
	description: Type.Optional(Type.String({ description: "Detailed vulnerability description" })),
	impact: Type.Optional(Type.String({ description: "Business/security impact" })),
	steps: Type.Optional(Type.String({ description: "Reproduction steps" })),
	affectedEndpoint: Type.Optional(Type.String({ description: "Affected URL/endpoint" })),
	remediation: Type.Optional(Type.String({ description: "Suggested fix" })),
	fileName: Type.Optional(Type.String({ description: "Output filename (for export action)" })),
	appendNotepad: Type.Optional(Type.Boolean({ description: "Append report to notepad notes. Default: true.", default: true })),
});

interface ReportDetails {
	platform: string;
	title?: string;
	severity?: string;
	filePath?: string;
	error?: string;
}

function formatIntigritiReport(params: Record<string, unknown>): string {
	const title = (params.title as string) || "Vulnerability Report";
	const severity = ((params.severity as string) || "medium").toLowerCase();
	const category = (params.category as string) || "other";
	const description = (params.description as string) || "";
	const impact = (params.impact as string) || "";
	const steps = (params.steps as string) || "";
	const endpoint = (params.affectedEndpoint as string) || "";
	const remediation = (params.remediation as string) || "";

	return `# ${title}

## Summary
- **Severity**: ${severity.toUpperCase()}
- **Category**: ${category}
- **Affected Endpoint**: ${endpoint || "See reproduction steps"}

## Description
${description || "(no description provided)"}

## Impact
${impact || "(no impact provided)"}

## Steps to Reproduce
${steps || "(no steps provided)"}

## Remediation
${remediation || "(no remediation suggested)"}

---
*Report generated for Intigriti submission*
`;
}

function formatHackerOneReport(params: Record<string, unknown>): string {
	const title = (params.title as string) || "Vulnerability Report";
	const severity = ((params.severity as string) || "medium").toLowerCase();
	const category = (params.category as string) || "other";
	const description = (params.description as string) || "";
	const impact = (params.impact as string) || "";
	const steps = (params.steps as string) || "";
	const endpoint = (params.affectedEndpoint as string) || "";
	const remediation = (params.remediation as string) || "";

	return `# ${title}

**Severity:** ${severity.charAt(0).toUpperCase() + severity.slice(1)}
**Weakness:** ${category.replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase())}

## Summary
${description || "(no description provided)"}

## Impact
${impact || "(no impact provided)"}

## Reproduction
${steps || "(no steps provided)"}
${endpoint ? `\n**Affected URL:** ${endpoint}` : ""}

## Suggested Fix
${remediation || "(no remediation suggested)"}

---
*Report generated for HackerOne submission*
`;
}

function formatBugcrowdReport(params: Record<string, unknown>): string {
	const title = (params.title as string) || "Vulnerability Report";
	const severity = ((params.severity as string) || "medium").toLowerCase();
	const category = (params.category as string) || "other";
	const description = (params.description as string) || "";
	const impact = (params.impact as string) || "";
	const steps = (params.steps as string) || "";
	const endpoint = (params.affectedEndpoint as string) || "";
	const remediation = (params.remediation as string) || "";

	// Bugcrowd uses priority levels
	const priorityMap: Record<string, string> = {
		critical: "P1",
		high: "P2",
		medium: "P3",
		low: "P4",
		informational: "P5",
	};

	return `# ${title}

**Priority:** ${priorityMap[severity] || "P3"}
**Vulnerability Class:** ${category.replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase())}
**Affected Target:** ${endpoint || "See steps below"}

## Description
${description || "(no description provided)"}

## Business Impact
${impact || "(no impact provided)"}

## Steps to Reproduce
${steps || "(no steps provided)"}

## Mitigation
${remediation || "(no remediation suggested)"}

---
*Report generated for Bugcrowd submission*
`;
}

function getTemplate(platform: string): string {
	switch (platform) {
		case "intigriti":
			return formatIntigritiReport({
				title: "[VULNERABILITY TITLE]",
				severity: "medium",
				category: "other",
				description: "[DETAILED DESCRIPTION]",
				impact: "[BUSINESS/SECURITY IMPACT]",
				steps: "[REPRODUCTION STEPS]",
				affectedEndpoint: "[AFFECTED URL/ENDPOINT]",
				remediation: "[SUGGESTED FIX]",
			});
		case "hackerone":
			return formatHackerOneReport({
				title: "[VULNERABILITY TITLE]",
				severity: "medium",
				category: "other",
				description: "[DETAILED DESCRIPTION]",
				impact: "[BUSINESS/SECURITY IMPACT]",
				steps: "[REPRODUCTION STEPS]",
				affectedEndpoint: "[AFFECTED URL/ENDPOINT]",
				remediation: "[SUGGESTED FIX]",
			});
		case "bugcrowd":
			return formatBugcrowdReport({
				title: "[VULNERABILITY TITLE]",
				severity: "medium",
				category: "other",
				description: "[DETAILED DESCRIPTION]",
				impact: "[BUSINESS/SECURITY IMPACT]",
				steps: "[REPRODUCTION STEPS]",
				affectedEndpoint: "[AFFECTED URL/ENDPOINT]",
				remediation: "[SUGGESTED FIX]",
			});
		default:
			return "Unknown platform";
	}
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "report_generator",
		label: "Report Generator",
		description: "Generate bug bounty vulnerability reports formatted for Intigriti, HackerOne, or Bugcrowd. Actions: generate (full report), template (blank template), export (save to file)",
		parameters: ReportParams,
		promptSnippet: "Generate a [platform] vulnerability report with title, severity, description, impact, steps, endpoint, and remediation",
		promptGuidelines: [
			"Generate reports using report_generator with action=generate once a vulnerability is confirmed",
			"Use action=template to see a platform's report format before writing",
			"Always include: title, severity, category, description, impact, steps, affected endpoint, remediation",
			"Be precise in reproduction steps — include exact URLs, payloads, and screenshots references",
		],

		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			const platform = params.platform;
			const reportsDir = join(process.cwd(), "reports");

			switch (params.action) {
				case "template": {
					const tmpl = getTemplate(platform);
					return {
						content: [{ type: "text", text: tmpl }],
						details: { platform } as ReportDetails,
					};
				}

			case "generate": {
				let report: string;
				const reportParams = params as unknown as Record<string, unknown>;
				switch (platform) {
					case "intigriti":
						report = formatIntigritiReport(reportParams);
						break;
					case "hackerone":
						report = formatHackerOneReport(reportParams);
						break;
					case "bugcrowd":
						report = formatBugcrowdReport(reportParams);
						break;
					default:
						return {
							content: [{ type: "text", text: `Unknown platform: ${platform}. Use intigriti, hackerone, or bugcrowd.` }],
							details: { platform, error: "unknown platform" } as ReportDetails,
						};
				}

				// Auto-save generated report to disk
				let filePath = "";
				if (params.title) {
					if (!existsSync(reportsDir)) {
						mkdirSync(reportsDir, { recursive: true });
					}
					const safeTitle = (params.title as string).replace(/[^a-zA-Z0-9_-]+/g, "_").slice(0, 80);
					const fileName = params.fileName || `${platform}-${safeTitle}-${Date.now()}.md`;
					filePath = join(reportsDir, fileName);
					try {
						writeFileSync(filePath, report, "utf-8");
					} catch (_err) {
						// File write failed, still return the inline report
					}
				}

				const fileNote = filePath ? `\n\n---\nReport saved to ${filePath}` : "";
				return {
					content: [{ type: "text", text: report + fileNote }],
					details: {
						platform,
						title: params.title,
						severity: params.severity,
						filePath: filePath || undefined,
					} as ReportDetails,
				};
			}

				case "export": {
					if (!params.title) {
						return {
							content: [{ type: "text", text: "Error: title required for export" }],
							details: { platform, error: "title required" } as ReportDetails,
						};
					}
					const reportParams2 = params as unknown as Record<string, unknown>;
					let report: string;
					switch (platform) {
						case "intigriti":
							report = formatIntigritiReport(reportParams2);
							break;
						case "hackerone":
							report = formatHackerOneReport(reportParams2);
							break;
						case "bugcrowd":
							report = formatBugcrowdReport(reportParams2);
							break;
						default:
							return {
								content: [{ type: "text", text: `Unknown platform: ${platform}` }],
								details: { platform, error: "unknown platform" } as ReportDetails,
							};
					}

					if (!existsSync(reportsDir)) {
						mkdirSync(reportsDir, { recursive: true });
					}
					const safeTitle = (params.title as string).replace(/[^a-zA-Z0-9_-]+/g, "_").slice(0, 80);
					const fileName = params.fileName || `${platform}-${safeTitle}-${Date.now()}.md`;
					const filePath = join(reportsDir, fileName);

					try {
						writeFileSync(filePath, report, "utf-8");
						return {
							content: [{ type: "text", text: `Report exported to ${filePath}` }],
							details: { platform, title: params.title, severity: params.severity, filePath } as ReportDetails,
						};
					} catch (err: unknown) {
						const msg = err instanceof Error ? err.message : String(err);
						return {
							content: [{ type: "text", text: `Export failed: ${msg}` }],
							details: { platform, error: msg } as ReportDetails,
						};
					}
				}

				default:
					return {
						content: [{ type: "text", text: `Unknown action: ${params.action}. Use generate, template, or export.` }],
						details: { platform, error: "unknown action" } as ReportDetails,
					};
			}
		},

		renderCall(args, theme, _context) {
			const platform = (args.platform as string) || "...";
			const action = (args.action as string) || "generate";
			const icon = platform === "intigriti" ? "I" : platform === "hackerone" ? "H1" : platform === "bugcrowd" ? "BC" : "?";
			let text =
				theme.fg("toolTitle", theme.bold("report ")) +
				theme.fg("accent", icon) +
				" " +
				theme.fg("muted", action);
			if (args.title) {
				const preview = (args.title as string).length > 40 ? `${(args.title as string).slice(0, 40)}...` : args.title;
				text += `\n  ${theme.fg("dim", preview)}`;
				if (args.severity) {
					const sevColor = { critical: "error", high: "warning", medium: "accent", low: "dim", informational: "muted" }[
						args.severity as string
					] || "muted";
					text += ` ${theme.fg(sevColor, (args.severity as string).toUpperCase())}`;
				}
			}
			return new Text(text, 0, 0);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as ReportDetails | undefined;
			if (!details) {
				const text = result.content[0];
				return new Text(text?.type === "text" ? text.text : "", 0, 0);
			}
			if (details.error) {
				return new Text(theme.fg("error", `Error: ${details.error}`), 0, 0);
			}
			if (details.filePath) {
				return new Text(theme.fg("success", "✓ ") + theme.fg("muted", `Exported to ${details.filePath}`), 0, 0);
			}
			const severityLabel = details.severity ? ` [${details.severity.toUpperCase()}]` : "";
			const platformLabel = details.platform.toUpperCase();
			return new Text(
				theme.fg("success", "✓ ") +
					theme.fg("accent", platformLabel) +
					theme.fg("muted", severityLabel),
				0,
				0,
			);
		},
	});
}
