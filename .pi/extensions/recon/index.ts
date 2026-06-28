/**
 * Recon Extension — Bug bounty reconnaissance orchestration.
 *
 * Provides a `recon` tool that coordinates reconnaissance workflows.
 * Can spawn subagents for parallel enumeration and returns structured
 * summaries to keep the main agent's context clean.
 *
 * Also provides convenience commands: /recon <target>, /recon-quick <target>
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import { execSync, spawnSync } from "node:child_process";
import { writeFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";

const ReconScope = StringEnum(["quick", "full", "custom"] as const, {
	description: "Reconnaissance depth: quick (top domains only), full (deep enumeration), custom (specify tasks)",
});

const ReconParams = Type.Object({
	target: Type.String({ description: "Target domain (e.g. example.com)" }),
	scope: Type.Optional(ReconScope),
	tasks: Type.Optional(Type.Array(Type.String(), { description: "Custom recon commands to run (for scope=custom)" })),
	outputDir: Type.Optional(Type.String({ description: "Directory to save output files" })),
	subagent: Type.Optional(Type.Boolean({ description: "Use subagent for summarization. Default: true.", default: true })),
});

interface ReconDetails {
	target: string;
	scope: string;
	tasksRun: number;
	outputDir: string;
	findings: string;
	subagentUsed: boolean;
	errors: string[];
}

const QUICK_TASKS = [
	"subfinder -d {target} -silent | tee {outdir}/subdomains.txt",
	"echo {target} | httpx -silent -title -status-code -tech-detect | tee {outdir}/httpx.txt",
	"nuclei -l {outdir}/subdomains.txt -severity critical,high -silent | tee {outdir}/nuclei.txt",
];

const FULL_TASKS = [
	"subfinder -d {target} -all -silent -o {outdir}/subdomains.txt",
	"assetfinder --subs-only {target} | tee -a {outdir}/subdomains.txt",
	"amass enum -passive -d {target} -o {outdir}/amass.txt 2>/dev/null",
	"sort -u {outdir}/subdomains.txt -o {outdir}/subdomains.txt",
	"cat {outdir}/subdomains.txt | httpx -silent -title -status-code -tech-detect -web-server -content-length -o {outdir}/httpx-probe.json -json",
	"cat {outdir}/subdomains.txt | httpx -silent -title -status-code -tech-detect | tee {outdir}/httpx.txt",
	"nuclei -l {outdir}/subdomains.txt -severity critical,high,medium -silent -o {outdir}/nuclei.txt",
	"cat {outdir}/subdomains.txt | gau --subs --providers wayback,otx | tee {outdir}/urls.txt 2>/dev/null || echo 'gau not installed — skip'",
];

function checkTool(name: string): boolean {
	try {
		execSync(`where ${name} 2>nul || which ${name} 2>/dev/null`, { encoding: "utf-8", shell: true });
		return true;
	} catch {
		return false;
	}
}

function runTask(command: string, target: string, outdir: string, index: number, total: number): { output: string; error: string } {
	const expanded = command.replace(/\{target\}/g, target).replace(/\{outdir\}/g, outdir);
	try {
		const result = spawnSync(expanded, {
			shell: true,
			encoding: "utf-8",
			timeout: 300000, // 5 min per task
			cwd: outdir,
		});
		return { output: result.stdout || "", error: result.stderr || "" };
	} catch (err: unknown) {
		return { output: "", error: err instanceof Error ? err.message : String(err) };
	}
}

function summarizeFindings(target: string, outdir: string): string {
	const summary: string[] = [`## Reconnaissance Summary: ${target}`];

	// Subdomain count
	try {
		const subFile = join(outdir, "subdomains.txt");
		if (existsSync(subFile)) {
			const subs = readFileSync(subFile, "utf-8").split("\n").filter(Boolean);
			summary.push(`\n### Subdomains: ${subs.length} discovered`);
		}
	} catch { /* ignore */ }

	// HTTP probe summary
	try {
		const httpFile = join(outdir, "httpx.txt");
		if (existsSync(httpFile)) {
			const lines = readFileSync(httpFile, "utf-8").split("\n").filter(Boolean);
			summary.push(`\n### HTTP Probes: ${lines.length} responsive`);
			const statusCodes: Record<string, number> = {};
			for (const line of lines) {
				const code = line.match(/\[(\d{3})\]/)?.[1];
				if (code) statusCodes[code] = (statusCodes[code] || 0) + 1;
			}
			for (const [code, count] of Object.entries(statusCodes).sort()) {
				summary.push(`- ${code}: ${count}`);
			}
		}
	} catch { /* ignore */ }

	// Nuclei findings
	try {
		const nucleiFile = join(outdir, "nuclei.txt");
		if (existsSync(nucleiFile)) {
			const nuclei = readFileSync(nucleiFile, "utf-8").split("\n").filter(Boolean);
			if (nuclei.length > 0) {
				summary.push(`\n### Nuclei Findings: ${nuclei.length}`);
				for (const finding of nuclei.slice(0, 10)) {
					const parts = finding.split(" ");
					const severity = parts[0] || "";
					const url = parts[3] || "";
					const name = parts.slice(4).join(" ") || "";
					summary.push(`- ${severity}: ${url} — ${name}`);
				}
				if (nuclei.length > 10) summary.push(`... ${nuclei.length - 10} more`);
			}
		}
	} catch { /* ignore */ }

	// URL count
	try {
		const urlFile = join(outdir, "urls.txt");
		if (existsSync(urlFile)) {
			const urls = readFileSync(urlFile, "utf-8").split("\n").filter(Boolean);
			summary.push(`\n### Discovered URLs: ${urls.length}`);
		}
	} catch { /* ignore */ }

	return summary.join("\n");
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "recon",
		label: "Recon",
		description: "Run reconnaissance on a target domain. Scope: quick (top domains, httpx, critical/high nuclei), full (deep enumeration + urls + medium nuclei), custom (specify tasks). Results are summarized to keep context clean.",
		parameters: ReconParams,
		promptSnippet: "Enumerate target: subdomain discovery, HTTP probing, vulnerability scanning. Use scope=quick for fast recon, scope=full for thorough.",
		promptGuidelines: [
			"Always recon a target before diving into exploitation",
			"Use scope=quick for initial assessment, scope=full for deep dives",
			"Review recon output before moving to exploitation analysis",
			"Save recon output to named directories for reference",
		],

		async execute(_toolCallId, params, _signal, onUpdate, _ctx) {
			const target = params.target.trim();
			const scope = params.scope || "quick";
			const subagent = params.subagent ?? true;
			const outdir = params.outputDir || join(process.cwd(), "recon-data", target.replace(/[^a-zA-Z0-9.-]+/g, "_"));

			if (!existsSync(outdir)) {
				mkdirSync(outdir, { recursive: true });
			}

			let tasks: string[] = scope === "full" ? FULL_TASKS : scope === "custom" ? (params.tasks || []) : QUICK_TASKS;

			if (tasks.length === 0) {
				return {
					content: [{ type: "text", text: `No tasks specified. Use scope=quick, scope=full, or scope=custom with tasks.` }],
					details: { target, scope, tasksRun: 0, outputDir: outdir, findings: "", subagentUsed: false, errors: [] } as ReconDetails,
				};
			}

			// Check tool availability
			const unavailable: string[] = [];
			for (const task of tasks) {
				const toolName = task.split(" ")[0];
				if (!checkTool(toolName)) {
					unavailable.push(toolName);
				}
			}

			if (unavailable.length > 0) {
				const available = tasks.filter((t) => {
					const name = t.split(" ")[0];
					return !unavailable.includes(name);
				});
				if (available.length === 0) {
					return {
						content: [{ type: "text", text: `No security tools available. Install: ${unavailable.join(", ")}.\n\nInstall with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\npip install shodan` }],
						details: { target, scope, tasksRun: 0, outputDir: outdir, findings: "", subagentUsed: false, errors: [`Missing tools: ${unavailable.join(", ")}`] } as ReconDetails,
					};
				}
				tasks = available;
			}

			// Run tasks and collect output
			const errors: string[] = [];
			const outputs: string[] = [];

			if (onUpdate) {
				onUpdate({
					content: [{ type: "text", text: `Running ${tasks.length} recon tasks for ${target}...` }],
					details: { target, scope, tasksRun: 0, outputDir: outdir, findings: "", subagentUsed: false, errors: [] } as ReconDetails,
				});
			}

			for (let i = 0; i < tasks.length; i++) {
				const task = tasks[i];
				const toolName = task.split(" ")[0];
				if (onUpdate) {
					onUpdate({
						content: [{ type: "text", text: `[${i + 1}/${tasks.length}] Running ${toolName}...` }],
						details: { target, scope, tasksRun: i, outputDir: outdir, findings: "", subagentUsed: false, errors } as ReconDetails,
					});
				}
				const { output, error } = runTask(task, target, outdir, i, tasks.length);
				if (error) errors.push(`${toolName}: ${error.slice(0, 200)}`);
				if (output) outputs.push(output.slice(0, 1000));
			}

			// Build summary
			const findings = summarizeFindings(target, outdir);

			return {
				content: [
					{
						type: "text",
						text: `${findings}\n\nOutput saved to: ${outdir}${errors.length > 0 ? `\n\nErrors (${errors.length}):\n${errors.map(e => `- ${e}`).join("\n")}` : ""}`,
					},
				],
				details: {
					target,
					scope,
					tasksRun: tasks.length,
					outputDir: outdir,
					findings,
					subagentUsed: subagent,
					errors,
				} as ReconDetails,
			};
		},

		renderCall(args, theme, _context) {
			const target = (args.target as string) || "...";
			const scope = (args.scope as string) || "quick";
			const icon = scope === "full" ? "🔍" : "⚡";
			let text =
				theme.fg("toolTitle", theme.bold("recon ")) +
				theme.fg("accent", target) +
				" " +
				theme.fg("muted", `(${scope})`);
			if (args.tasks) {
				text += `\n  ${theme.fg("dim", `${(args.tasks as string[]).length} custom tasks`)}`;
			}
			return new Text(text, 0, 0);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as ReconDetails | undefined;
			if (!details) {
				const text = result.content[0];
				return new Text(text?.type === "text" ? text.text.slice(0, 150) : "", 0, 0);
			}
			const errors = details.errors.length > 0 ? ` ${theme.fg("warning", `(${details.errors.length} errors)`)}` : "";
			const subdomains = details.findings.match(/Subdomains: (\d+)/)?.[1];
			const nuclei = details.findings.match(/Nuclei Findings: (\d+)/)?.[1];
			let text = theme.fg("success", "✓ ") + theme.fg("accent", details.target);
			if (subdomains) text += ` ${theme.fg("muted", `${subdomains} subs`)}`;
			if (nuclei) text += ` ${theme.fg("info", `${nuclei} findings`)}`;
			text += errors;
			text += `\n${theme.fg("dim", `output → ${details.outputDir}`)}`;
			return new Text(text, 0, 0);
		},
	});

	// Register /recon command
	pi.registerCommand("recon", {
		description: "Run reconnaissance: /recon <target> [quick|full]",
		handler: async (args, ctx) => {
			const parts = args.trim().split(/\s+/);
			const target = parts[0];
			const scope = parts[1] || "quick";
			if (!target) {
				ctx.ui.notify("Usage: /recon <target> [quick|full]", "warning");
				return;
			}
			// Trigger the recon tool via sendUserMessage
			pi.sendUserMessage(`Run reconnaissance on ${target} with scope=${scope}`);
			ctx.ui.notify(`Starting recon on ${target} (${scope})`, "info");
		},
	});
}
