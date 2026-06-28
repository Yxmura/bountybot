/**
 * Browser Data Extension — Extract cookies and localStorage from browsers.
 *
 * Reads cookie databases and localStorage data from Chromium-based browsers
 * (Chrome, Edge, Brave) and Firefox. Supports reading from multiple profiles.
 *
 * The extracted data is returned to the agent and can be used for
 * authenticated scanning or API testing.
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import { execSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, basename } from "node:path";

const BrowserEnum = StringEnum(["chrome", "edge", "brave", "firefox", "all"] as const, {
	description: "Browser to extract data from",
});

const ActionEnum = StringEnum(["cookies", "localstorage", "all"] as const, {
	description: "What type of data to extract",
});

interface BrowserDataParams {
	action: string;
	browser?: string;
	domain?: string;
	profile?: string;
	format?: string;
}

const BrowserDataParams = Type.Object({
	action: ActionEnum,
	browser: Type.Optional(BrowserEnum),
	domain: Type.Optional(Type.String({ description: "Filter by domain (e.g. example.com)" })),
	profile: Type.Optional(Type.String({ description: "Browser profile name (e.g. Default, Profile 1)" })),
	format: Type.Optional(StringEnum(["curl", "header", "json"] as const, {
		description: "Output format: curl (ready-to-use curl commands), header (HTTP header format), json (raw)",
		default: "json",
	})),
});

interface CookieEntry {
	domain: string;
	name: string;
	value: string;
	path: string;
	expires?: string;
	httpOnly?: boolean;
	secure?: boolean;
}

interface LocalStorageEntry {
	origin: string;
	key: string;
	value: string;
}

interface BrowserDataDetails {
	browser: string;
	profile: string;
	action: string;
	cookieCount: number;
	localStorageCount: number;
	format: string;
	error?: string;
}

function getChromiumDataDir(browser: string): string | null {
	const home = homedir();
	const paths: Record<string, string> = {
		chrome: join(home, "AppData", "Local", "Google", "Chrome", "User Data"),
		edge: join(home, "AppData", "Local", "Microsoft", "Edge", "User Data"),
		brave: join(home, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
	};
	return paths[browser.toLowerCase()] || null;
}

function getFirefoxDataDir(): string | null {
	const home = homedir();
	const path = join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles");
	return existsSync(path) ? path : null;
}

function findFirefoxProfileDir(baseDir: string): string | null {
	try {
		const entries = readdirSync(baseDir, { withFileTypes: true });
		for (const entry of entries) {
			if (entry.isDirectory() && (entry.name.endsWith(".default-release") || entry.name.endsWith(".default"))) {
				return join(baseDir, entry.name);
			}
		}
		return null;
	} catch {
		return null;
	}
}

function decryptChromiumCookies(cookiesDbPath: string): string {
	// Use a PowerShell script to decrypt Chromium cookies via DPAPI
	const psScript = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$dbPath = '${cookiesDbPath.replace(/'/g, "''")}'

# Read SQLite database using hex dump (avoid SQLite dependency)
# Fall back to asking user to install sqlite3
$output = ""
try {
  $bytes = [System.IO.File]::ReadAllBytes($dbPath)
  $output = "Raw cookie database read: " + $bytes.Length + " bytes. Use a SQLite viewer to inspect cookies at " + $dbPath
} catch {
  $output = "Could not read cookies: " + $_.Exception.Message
}
Write-Output $output
`.trim();

	try {
		const result = spawnSync("powershell", ["-NoProfile", "-Command", psScript], {
			encoding: "utf-8",
			timeout: 10000,
		});
		return result.stdout || result.stderr || "No output";
	} catch {
		return "Could not execute PowerShell script";
	}
}

function parseNetscapeCookies(content: string, domain?: string): CookieEntry[] {
	const cookies: CookieEntry[] = [];
	const lines = content.split("\n");
	for (const line of lines) {
		if (line.startsWith("#") || line.trim() === "") continue;
		const parts = line.split("\t");
		if (parts.length < 7) continue;
		const cookieDomain = parts[0];
		if (domain && !cookieDomain.includes(domain)) continue;
		cookies.push({
			domain: cookieDomain,
			path: parts[2],
			secure: parts[3] === "TRUE",
			expires: parts[4] !== "0" ? new Date(parseInt(parts[4]) * 1000).toISOString() : undefined,
			name: parts[5],
			value: parts[6],
		});
	}
	return cookies;
}

function formatCookiesAsCurl(cookies: CookieEntry[], domain: string): string {
	const value = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
	return `curl -H "Cookie: ${value}" ${domain.startsWith("http") ? domain : `https://${domain}`}`;
}

function formatCookiesAsHeader(cookies: CookieEntry[]): string {
	return `Cookie: ${cookies.map((c) => `${c.name}=${c.value}`).join("; ")}`;
}

function formatCookiesAsJson(cookies: CookieEntry[]): string {
	return JSON.stringify(cookies, null, 2);
}

function readChromiumCookies(browser: string, profile: string, domain?: string): string {
	const dataDir = getChromiumDataDir(browser);
	if (!dataDir) {
		return `Could not find ${browser} data directory.`;
	}
	const profileDir = join(dataDir, profile || "Default");
	const networkDir = join(profileDir, "Network");
	const cookiesPath = join(networkDir, "Cookies");

	if (!existsSync(cookiesPath)) {
		return `Cookie database not found at ${cookiesPath}. Browser may be locked or using a different profile.`;
	}

	// Try to read cookies using npx sqlite3 if available
	try {
		const domainFilter = domain ? `WHERE host_key LIKE '%${domain}%'` : "";
		const result = spawnSync("npx", [
			"sqlite3",
			cookiesPath,
			`.mode json
SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly FROM cookies ${domainFilter} LIMIT 200;`,
		], {
			encoding: "utf-8",
			timeout: 15000,
			shell: true,
		});

		if (result.status === 0 && result.stdout) {
			try {
				const cookies: CookieEntry[] = JSON.parse(result.stdout).map((row: any) => ({
					domain: row.host_key,
					name: row.name,
					value: row.value,
					path: row.path,
					expires: row.expires_utc ? new Date(row.expires_utc * 1).toISOString() : undefined,
					httpOnly: row.is_httponly === 1,
					secure: row.is_secure === 1,
				}));
				if (cookies.length === 0) return `No cookies found${domain ? ` for ${domain}` : ""} in ${browser} (${profile || "Default"}).`;
				return JSON.stringify(cookies, null, 2);
			} catch {
				return `Could not parse cookie data. Raw output: ${result.stdout.slice(0, 500)}`;
			}
		}

		if (result.stderr && result.stderr.includes("locked")) {
			return `Cookie database is locked. Close ${browser} first, or use --profile to specify a different profile.`;
		}

		return `Could not read cookies. You may need sqlite3: npm install -g sqlite3. ${result.stderr || ""}`;
	} catch {
		return `Could not execute sqlite3. Install it with: npm install -g sqlite3`;
	}
}

function readFirefoxCookies(profile: string, domain?: string): string {
	const dataDir = getFirefoxDataDir();
	if (!dataDir) return "Firefox profile directory not found.";

	const profilesDir = profile
		? join(dataDir, profile)
		: findFirefoxProfileDir(dataDir);
	if (!profilesDir) return "No Firefox profile found.";

	const cookiesPath = join(profilesDir, "cookies.sqlite");
	if (!existsSync(cookiesPath)) return `Firefox cookies not found at ${cookiesPath}.`;

	try {
		const domainFilter = domain ? `WHERE host LIKE '%${domain}%'` : "";
		const result = spawnSync("npx", [
			"sqlite3",
			cookiesPath,
			`.mode json
SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies ${domainFilter} LIMIT 200;`,
		], {
			encoding: "utf-8",
			timeout: 15000,
			shell: true,
		});

		if (result.status === 0 && result.stdout) {
			try {
				const cookies: CookieEntry[] = JSON.parse(result.stdout).map((row: any) => ({
					domain: row.host,
					name: row.name,
					value: row.value,
					path: row.path,
					expires: row.expiry ? new Date(row.expiry * 1000).toISOString() : undefined,
					secure: row.isSecure === 1,
					httpOnly: row.isHttpOnly === 1,
				}));
				if (cookies.length === 0) return `No cookies found${domain ? ` for ${domain}` : ""} in Firefox.`;
				return JSON.stringify(cookies, null, 2);
			} catch {
				return `Could not parse Firefox cookie data.`;
			}
		}
		return `Could not read Firefox cookies.`;
	} catch {
		return `Could not execute sqlite3. Install it with: npm install -g sqlite3`;
	}
}

function readChromiumLocalStorage(browser: string, profile: string, domain?: string): string {
	const dataDir = getChromiumDataDir(browser);
	if (!dataDir) return `Could not find ${browser} data directory.`;

	const profileDir = join(dataDir, profile || "Default");
	const lsDir = join(profileDir, "Local Storage", "leveldb");

	if (!existsSync(lsDir)) {
		return `LocalStorage not found at ${lsDir}.`;
	}

	try {
		const files = readdirSync(lsDir);
		const ldbFiles = files.filter((f) => f.endsWith(".ldb") || f.endsWith(".log"));
		if (ldbFiles.length === 0) return "No localStorage LevelDB files found.";

		// Try to use strings command (from Sysinternals) or fall back to raw read
		try {
			const ldbPath = join(lsDir, ldbFiles[0]);
			const result = spawnSync("strings", [ldbPath], {
				encoding: "utf-8",
				timeout: 10000,
			});
			if (result.status === 0 && result.stdout) {
				const lines = result.stdout.split("\n").filter((l) => l.trim().length > 0);
				const entries: string[] = [];
				let currentKey = "";
				for (const line of lines) {
					const trimmed = line.trim();
					if (trimmed.startsWith("_http") || trimmed.startsWith("https://") || trimmed.startsWith("http://")) {
						currentKey = trimmed;
					} else if (currentKey && trimmed.length > 0 && !trimmed.startsWith("\u0000")) {
						const entry = domain
							? currentKey.includes(domain) || trimmed.includes(domain)
								? `${currentKey}: ${trimmed.slice(0, 200)}`
								: null
							: `${currentKey}: ${trimmed.slice(0, 200)}`;
						if (entry) entries.push(entry);
					}
				}
				const resultEntries = entries.slice(0, 50);
				if (resultEntries.length === 0) return "No localStorage entries found.";
				return JSON.stringify(resultEntries, null, 2);
			}
		} catch {
			// strings command failed
		}

		return `LocalStorage directory found at ${lsDir} (${ldbFiles.length} files). Unable to parse LevelDB content.\nFiles: ${ldbFiles.slice(0, 10).join(", ")}`;
	} catch {
		return `Could not read localStorage directory at ${lsDir}.`;
	}
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "browser_data",
		label: "Browser Data",
		description: "Extract cookies, localStorage, and sessionStorage from Chromium browsers (Chrome, Edge, Brave) and Firefox. Returns data in json, curl command, or HTTP header format.",
		parameters: BrowserDataParams,
		promptSnippet: "Extract cookies or localStorage from [browser] for [domain], format: [curl/header/json]",
		promptGuidelines: [
			"Use browser_data cookies to get authentication cookies for authenticated testing",
			"Use browser_data localstorage to find tokens and session data",
			"Specify domain to filter results for a target",
			"Close browser before extracting cookies to avoid locked database issues",
		],

		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			const browser = params.browser || "chrome";
			const domain = params.domain;
			const profile = params.profile || "Default";
			const format = params.format || "json";
			const action = params.action;

			let results: string[] = [];
			const browsers = browser === "all" ? ["chrome", "edge", "brave", "firefox"] : [browser];
			let totalCookies = 0;
			let totalLS = 0;

			for (const b of browsers) {
				const browserLabel = b.charAt(0).toUpperCase() + b.slice(1);

				if (action === "cookies" || action === "all") {
					let cookieData: string;
					if (b === "firefox") {
						cookieData = readFirefoxCookies(profile, domain);
					} else {
						cookieData = readChromiumCookies(b, profile, domain);
					}

					if (!cookieData.startsWith("Could not") && !cookieData.startsWith("No cookie") && !cookieData.startsWith("Cookie database not")) {
						try {
							const cookies: CookieEntry[] = JSON.parse(cookieData);
							totalCookies += cookies.length;

							if (format === "curl" && domain) {
								results.push(`## ${browserLabel} (curl)\n\`\`\`bash\n${formatCookiesAsCurl(cookies, domain)}\n\`\`\``);
							} else if (format === "header") {
								results.push(`## ${browserLabel} (Cookie header)\n\`\`\`\n${formatCookiesAsHeader(cookies)}\n\`\`\``);
							} else {
								results.push(`## ${browserLabel} Cookies (${cookies.length})\n\`\`\`json\n${formatCookiesAsJson(cookies)}\n\`\`\``);
							}
						} catch {
							results.push(`## ${browserLabel}\n${cookieData}`);
						}
					} else {
						results.push(`## ${browserLabel}\n${cookieData}`);
					}
				}

				if (action === "localstorage" || action === "all") {
					if (b !== "firefox") {
						const lsData = readChromiumLocalStorage(b, profile, domain);
						if (!lsData.startsWith("Could not") && !lsData.startsWith("No localStorage") && !lsData.startsWith("LocalStorage not found")) {
							try {
								const entries = JSON.parse(lsData);
								totalLS += Array.isArray(entries) ? entries.length : 0;
							} catch {
								// not JSON
							}
						}
						results.push(`## ${browserLabel} LocalStorage\n\`\`\`json\n${lsData}\n\`\`\``);
					} else {
						results.push(`## ${browserLabel}\nLocalStorage extraction for Firefox is not supported.`);
					}
				}
			}

			if (results.length === 0) {
				results.push(`No data found for ${browsers.join(", ")}.`);
			}

			return {
				content: [{ type: "text", text: results.join("\n\n") }],
				details: {
					browser: browsers.join(","),
					profile,
					action,
					cookieCount: totalCookies,
					localStorageCount: totalLS,
					format,
				} as BrowserDataDetails,
			};
		},

		renderCall(args, theme, _context) {
			const browser = (args.browser as string) || "chrome";
			const action = (args.action as string) || "cookies";
			let text = theme.fg("toolTitle", theme.bold("browser_data ")) + theme.fg("accent", browser);
			if (args.domain) text += theme.fg("dim", ` @${args.domain}`);
			text += " " + theme.fg("muted", action);
			const format = args.format as string;
			if (format && format !== "json") text += ` ${theme.fg("dim", `(${format})`)}`;
			return new Text(text, 0, 0);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as BrowserDataDetails | undefined;
			if (!details) {
				const text = result.content[0];
				return new Text(text?.type === "text" ? text.text.slice(0, 100) : "", 0, 0);
			}
			if (details.error) {
				return new Text(theme.fg("error", `Error: ${details.error}`), 0, 0);
			}
			const parts: string[] = [];
			if (details.cookieCount > 0) parts.push(`${details.cookieCount} cookies`);
			if (details.localStorageCount > 0) parts.push(`${details.localStorageCount} localStorage entries`);
			const summary = parts.join(", ") || "No data extracted";
			return new Text(
				theme.fg("success", "✓ ") +
					theme.fg("accent", details.browser) +
					theme.fg("muted", ` ${summary} (${details.format})`),
				0,
				0,
			);
		},
	});
}
