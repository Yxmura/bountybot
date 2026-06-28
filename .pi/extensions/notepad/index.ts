/**
 * Notepad Extension — Timestamped note-taking for bug bounty sessions.
 *
 * Provides a `notepad` tool that the agent uses to record findings,
 * observations, endpoints, and progress in real time. Notes persist
 * across session branches via session entry details.
 *
 * Also provides /notepad and /notes commands for viewing notes.
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI, ExtensionContext, Theme } from "@earendil-works/pi-coding-agent";
import { Text, truncateToWidth } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

interface Note {
	id: number;
	timestamp: string;
	text: string;
}

interface NotepadDetails {
	action: "add" | "view" | "clear" | "export";
	notes: Note[];
	nextId: number;
	error?: string;
}

const NotepadParams = Type.Object({
	action: StringEnum(["add", "view", "clear", "export"] as const),
	text: Type.Optional(Type.String({ description: "Note text (for add). Prefix with category: e.g. [recon], [vuln], [info]" })),
	file: Type.Optional(Type.String({ description: "Export file path (for export action)" })),
});

class NotepadComponent {
	private notes: Note[];
	private theme: Theme;
	private onClose: () => void;

	constructor(notes: Note[], theme: Theme, onClose: () => void) {
		this.notes = notes;
		this.theme = theme;
		this.onClose = onClose;
	}

	handleInput(_data: string): void {
		this.onClose();
	}

	render(width: number): string[] {
		const th = this.theme;
		const lines: string[] = [];

		lines.push("");
		const title = th.fg("accent", " Bug Bounty Notes ");
		const headerLine =
			th.fg("borderMuted", "─".repeat(3)) + title + th.fg("borderMuted", "─".repeat(Math.max(0, width - 20)));
		lines.push(truncateToWidth(headerLine, width));
		lines.push("");

		if (this.notes.length === 0) {
			lines.push(truncateToWidth(`  ${th.fg("dim", "No notes yet. Use notepad add to record findings.")}`, width));
		} else {
			const categories: Record<string, number> = {};
			for (const n of this.notes) {
				const cat = n.text.match(/^\[(\w+)\]/)?.[1] ?? "general";
				categories[cat] = (categories[cat] || 0) + 1;
			}
			const summary = Object.entries(categories)
				.map(([k, v]) => `${k}: ${v}`)
				.join("  ");
			lines.push(truncateToWidth(`  ${th.fg("dim", summary)}  ${th.fg("muted", `${this.notes.length} total`)}`, width));
			lines.push("");

			// Show last 20 notes in collapsed view
			for (const note of this.notes.slice(-20)) {
				const time = th.fg("dim", `[${note.timestamp}]`);
				const id = th.fg("accent", `#${note.id}`);
				const cat = note.text.match(/^\[(\w+)\]/)?.[1];
				const catColor = cat ? th.fg("info", `[${cat}]`) : "";
				const body = note.text.replace(/^\[\w+\]\s*/, "");
				const truncated = body.length > 60 ? body.slice(0, 60) + "..." : body;
				const label = th.fg("bold", String(note.id).padStart(3, " "));
				lines.push(truncateToWidth(` ${label} ${id} ${catColor} ${truncated}  ${time}`, width));
			}

			if (this.notes.length > 20) {
				lines.push(truncateToWidth(`  ${th.fg("dim", `... ${this.notes.length - 20} older notes`)}`, width));
			}
		}

		lines.push("");
		lines.push(truncateToWidth(`  ${th.fg("dim", "Any key to close")}`, width));
		lines.push("");

		return lines;
	}

	invalidate(): void {}
}

export default function (pi: ExtensionAPI) {
	let notes: Note[] = [];
	let nextId = 1;

	const now = (): string => {
		const d = new Date();
		return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
	};

	const reconstructState = (ctx: ExtensionContext) => {
		notes = [];
		nextId = 1;
		for (const entry of ctx.sessionManager.getBranch()) {
			if (entry.type !== "message") continue;
			const msg = entry.message;
			if (msg.role !== "toolResult" || msg.toolName !== "notepad") continue;
			const details = msg.details as NotepadDetails | undefined;
			if (details) {
				notes = details.notes;
				nextId = details.nextId;
			}
		}
	};

	pi.on("session_start", async (_event, ctx) => reconstructState(ctx));
	pi.on("session_tree", async (_event, ctx) => reconstructState(ctx));

	pi.registerTool({
		name: "notepad",
		label: "Notepad",
		description: "Record timestamped notes during bug bounty sessions. Actions: add (with text), view (list notes), clear, export (to file)",
		parameters: NotepadParams,
		promptSnippet: "Record notes with `notepad add` using category prefixes: [recon], [vuln], [endpoint], [info]",
		promptGuidelines: [
			"Use notepad add for every finding — never assume you'll remember details later",
			"Prefix notes with category tags: [recon] [vuln] [endpoint] [info] [exploit] [report]",
			"Include the target domain/subdomain in every note for traceability",
		],

		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			switch (params.action) {
				case "add": {
					if (!params.text) {
						return {
							content: [{ type: "text", text: "Error: text required for add action" }],
							details: { action: "add", notes: [...notes], nextId, error: "text required" } as NotepadDetails,
						};
					}
					const newNote: Note = { id: nextId++, timestamp: now(), text: params.text };
					notes.push(newNote);
					return {
						content: [{ type: "text", text: `Note #${newNote.id} recorded: ${newNote.text}` }],
						details: { action: "add", notes: [...notes], nextId } as NotepadDetails,
					};
				}

				case "view": {
					if (notes.length === 0) {
						return {
							content: [{ type: "text", text: "No notes recorded yet." }],
							details: { action: "view", notes: [...notes], nextId } as NotepadDetails,
						};
					}
					const recent = notes.slice(-20);
					const lines = recent.map(
						(n) => `[#${n.id}] ${n.timestamp} — ${n.text}`,
					);
					const suffix = notes.length > 20 ? `\n... ${notes.length - 20} older notes (use export to dump all)` : "";
					return {
						content: [{ type: "text", text: `Notes (${notes.length} total):\n\n${lines.join("\n")}${suffix}` }],
						details: { action: "view", notes: [...notes], nextId } as NotepadDetails,
					};
				}

				case "clear": {
					const count = notes.length;
					notes = [];
					nextId = 1;
					return {
						content: [{ type: "text", text: `Cleared ${count} notes.` }],
						details: { action: "clear", notes: [], nextId: 1 } as NotepadDetails,
					};
				}

				case "export": {
					const filePath = params.file || join(process.cwd(), "bounty-notes.md");
					const md = notes.map(
						(n) => `### Note #${n.id} — ${n.timestamp}\n\n${n.text}\n`,
					).join("\n");
					try {
						writeFileSync(filePath, `# Bug Bounty Notes\n\n${md}`, "utf-8");
						return {
							content: [{ type: "text", text: `Exported ${notes.length} notes to ${filePath}` }],
							details: { action: "export", notes: [...notes], nextId } as NotepadDetails,
						};
					} catch (err: unknown) {
						const msg = err instanceof Error ? err.message : String(err);
						return {
							content: [{ type: "text", text: `Export failed: ${msg}` }],
							details: { action: "export", notes: [...notes], nextId, error: msg } as NotepadDetails,
						};
					}
				}

				default:
					return {
						content: [{ type: "text", text: `Unknown action: ${params.action}` }],
						details: { action: "view", notes: [...notes], nextId, error: "unknown action" } as NotepadDetails,
					};
			}
		},

		renderCall(args, theme, _context) {
			let text = theme.fg("toolTitle", theme.bold("notepad ")) + theme.fg("muted", args.action);
			if (args.text) {
				const preview = args.text.length > 40 ? `${(args.text as string).slice(0, 40)}...` : args.text;
				text += ` ${theme.fg("dim", `"${preview}"`)}`;
			}
			if (args.file) text += ` ${theme.fg("dim", "→")} ${theme.fg("accent", args.file)}`;
			return new Text(text, 0, 0);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as NotepadDetails | undefined;
			if (!details) {
				const text = result.content[0];
				return new Text(text?.type === "text" ? text.text : "", 0, 0);
			}
			if (details.error) {
				return new Text(theme.fg("error", `Error: ${details.error}`), 0, 0);
			}
			const noteCount = details.notes.length;
			switch (details.action) {
				case "add": {
					const latest = details.notes[details.notes.length - 1];
					return new Text(
						theme.fg("success", "✓ ") +
							theme.fg("accent", `#${latest.id}`) +
							" " +
							theme.fg("muted", latest.text),
						0,
						0,
					);
				}
				case "view":
					return new Text(theme.fg("muted", `${noteCount} note(s)`), 0, 0);
				case "clear":
					return new Text(theme.fg("warning", `Cleared ${noteCount} notes`), 0, 0);
				case "export":
					return new Text(theme.fg("success", `Exported ${noteCount} notes`), 0, 0);
			}
			return new Text(theme.fg("muted", `${noteCount} note(s)`), 0, 0);
		},
	});

	// Register /notepad command
	pi.registerCommand("notepad", {
		description: "View bug bounty notes",
		handler: async (_args, ctx) => {
			if (ctx.mode !== "tui") {
				ctx.ui.notify("/notepad requires interactive mode", "error");
				return;
			}
			await ctx.ui.custom<void>((_tui, theme, _kb, done) => {
				return new NotepadComponent(notes, theme, () => done());
			});
		},
	});

	// Register alias /notes
	pi.registerCommand("notes", {
		description: "View bug bounty notes (alias for /notepad)",
		handler: async (_args, ctx) => {
			if (ctx.mode !== "tui") {
				ctx.ui.notify("/notes requires interactive mode", "error");
				return;
			}
			await ctx.ui.custom<void>((_tui, theme, _kb, done) => {
				return new NotepadComponent(notes, theme, () => done());
			});
		},
	});
}
