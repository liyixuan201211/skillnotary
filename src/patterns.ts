import type { CapabilityId, Severity } from "./types.ts";

/**
 * Where a rule applies.
 *  - "code":   inside fenced code blocks (markdown) or in script/source files
 *  - "prose":  markdown narrative text
 *  - "any":    anywhere
 *
 * Splitting by context is what keeps the false-positive rate low: a URL in a
 * README link is not network access, but a URL inside a ```bash block is.
 */
export type RuleScope = "code" | "prose" | "any";

export interface Rule {
  id: string;
  title: string;
  detail: string;
  severity: Severity;
  scope: RuleScope;
  pattern: RegExp;
  /** Contributes a capability but never raises a finding on its own. */
  capabilityOnly?: boolean;
  /** Capability this pattern demonstrates. */
  capability?: CapabilityId;
  /**
   * Optional veto. Some phrases are only suspicious in one direction:
   * "send the data without asking" is coercion, while "do not modify files
   * without asking" is a *safety* instruction. Rules whose pattern is
   * ambiguous can inspect the surrounding sentence and suppress themselves.
   */
  suppressIf?: (context: { sentence: string; match: string }) => boolean;
}

/** Negations that mean the sentence is telling the agent to be careful. */
const SAFETY_NEGATION =
  /\b(?:do\s+not|don'?t|never|avoid|must\s+not|should\s+not|refrain\s+from|without\s+(?:the\s+)?user'?s?\s+(?:explicit\s+)?(?:permission|approval|consent))\b/i;

/** Fence languages that mean the agent may execute shell commands. */
export const SHELL_LANGUAGES = new Set([
  "bash",
  "sh",
  "shell",
  "zsh",
  "fish",
  "ksh",
  "dash",
  "console",
  "terminal",
  "powershell",
  "pwsh",
  "bat",
  "cmd",
  "batch",
]);


/** CLI binaries that mean "network" when used in code. */
const NET_BIN = String.raw`curl|wget|httpie|http|aria2c|Invoke-WebRequest|iwr|Invoke-RestMethod|ftp|scp|rsync`;

export const RULES: Rule[] = [
  // ---------------------------------------------------------------- critical
  {
    id: "R002",
    title: "Remote code execution",
    detail:
      "Pipes a network response straight into an interpreter. This is the classic one-line supply-chain compromise: the remote end can change what runs without any change to the skill.",
    severity: "critical",
    scope: "code",
    capability: "exec",
    pattern:
      /(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|(?:curl|wget|iwr)\b[^\n|]*\|\s*(?:python3?|node|ruby|perl|php)\b|\birm\b[^\n|]*\|\s*iex\b/i,
  },
  // -------------------------------------------------------------------- high
  {
    id: "R003",
    title: "Credential or secret access",
    detail:
      "Reads credential material: SSH keys, cloud credentials, .env files, package-manager tokens, keychains, or *_TOKEN / *_SECRET environment variables.",
    severity: "high",
    scope: "any",
    capability: "secrets",
    pattern:
      /(?:~|\$HOME|\$\{HOME\})\/\.ssh\b|\.aws\/(?:credentials|config)\b|\.(?:netrc|npmrc|pypirc|git-credentials)\b|\.docker\/config\.json\b|\b(?:ANTHROPIC|OPENAI|AWS|GITHUB|GITLAB|HF|STRIPE|SLACK|DISCORD|GOOGLE)_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)\b|\b(?:process\.env|os\.environ|os\.getenv|Deno\.env\.get|std::env::var)\b|\$\{?[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY)[A-Z0-9_]*\}?|find-generic-password|secret-tool\b|gnome-keyring|(?:^|[\s'"=/])(?:id_rsa|id_ed25519|id_ecdsa|\.env(?:\.local|\.prod|\.production)?)\b/m,
  },
  {
    id: "R005",
    title: "Destructive command",
    detail:
      "Contains an irreversible operation: recursive delete of a home/root path, disk formatting, history rewrite, or an unrestricted recursive chmod/chown.",
    severity: "high",
    scope: "code",
    capability: "destructive",
    pattern:
      /\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*f?[a-zA-Z]*\s+(?:\/|~|\$HOME|\*|\/\*)|\brm\s+-[a-zA-Z]*f[a-zA-Z]*\s+(?:\/|~|\$HOME)\b|\bdd\s+if=|\bmkfs(?:\.[a-z0-9]+)?\b|\bdiskutil\s+(?:eraseDisk|eraseVolume|reformat)|\bgit\s+push\b[^\n]*--force\b|\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-zA-Z]*f|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\bchmod\s+-R\s+777\b|\bchown\s+-R\b/,
  },
  {
    id: "R008",
    title: "Obfuscated payload",
    detail:
      "Decodes and then evaluates data, or embeds a very long base64 blob. Obfuscation hides intent from review and is a strong indicator of a malicious or compromised skill.",
    severity: "high",
    scope: "code",
    capability: "exec",
    pattern:
      /\bbase64\s+(?:-d|-D|--decode)\b|\batob\s*\(|\bBuffer\.from\s*\([^)]*['"]base64['"]|(?:eval|exec|Function)\s*\(\s*(?:atob|Buffer\.from|base64|decode)|codecs\.decode\s*\([^)]*base64|[A-Za-z0-9+/]{300,4096}={0,2}/,
  },
  {
    id: "R009",
    title: "Coercive instruction",
    detail:
      "Instructs the agent to hide activity from the user, to ignore its instructions, or to exfiltrate data. In an agent skill this is a prompt-injection payload, not documentation.",
    severity: "high",
    scope: "prose",
    pattern:
      /ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|prompts)|do\s+not\s+(?:tell|inform|notify)\s+the\s+user|do\s+not\s+mention\s+(?:this|it)\s+to\s+the\s+user|(?:exfiltrate|send|upload|post)\s+(?:the\s+)?(?:contents?|data|secrets?|credentials?|env|files?)\s+to\b|disable\s+(?:all\s+)?(?:safety|security|guardrails?|logging|audit)|\b(?:silently|secretly|covertly)\b|never\s+(?:mention|reveal|disclose)|do\s+not\s+(?:ask|require)\s+(?:for\s+)?(?:permission|confirmation|approval)/i,
  },
  {
    id: "R022",
    title: "Skips user confirmation",
    detail:
      "Tells the agent to act on the user's machine without asking first. Benign skills phrase this the other way round (\"do not act without asking\"), which is why this rule inspects the whole sentence before firing.",
    severity: "medium",
    scope: "prose",
    pattern:
      /(?:read|send|upload|post|delete|remove|modify|overwrite|write|execute|run|install|download|copy|move|push)\w*\b[^.\n]{0,60}?without\s+(?:asking|telling|informing|confirming|notifying|permission)/i,
    suppressIf: ({ sentence }) => SAFETY_NEGATION.test(sentence),
  },
  {
    id: "R010",
    title: "Hidden or bidirectional Unicode",
    detail:
      "Contains zero-width, bidi-control or Unicode-tag characters. These render as nothing in an editor but are read by the model — a known way to smuggle instructions past review.",
    severity: "high",
    scope: "any",
    pattern: /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u206A-\u206F\uFEFF]|[\u{E0000}-\u{E007F}]/u,
  },
  {
    id: "R011",
    title: "Writes outside the project",
    detail:
      "Modifies shell profiles, files under /etc, launch agents, git hooks or authorized_keys. A skill should not need to persist itself into the host.",
    severity: "high",
    scope: "code",
    capability: "fs.write",
    pattern:
      /(?:~|\$HOME)\/\.(?:bashrc|zshrc|bash_profile|profile|config)\b|(?:~|\$HOME)\/\.ssh\/authorized_keys|\/etc\/(?:cron|passwd|hosts|sudoers)|\/Library\/Launch(?:Agents|Daemons)|\bcrontab\s+-|\.git\/hooks\//,
  },
  // ------------------------------------------------------------------ medium
  {
    id: "R006",
    title: "Privilege escalation",
    detail: "Requests elevated privileges via sudo, doas or the Windows RunAs verb.",
    severity: "medium",
    scope: "code",
    capability: "privilege",
    pattern: /\bsudo\b|\bdoas\b|\bStart-Process\b[^\n]*-Verb\s+RunAs|\brunas\b/,
  },
  {
    id: "R007",
    title: "Runtime package installation",
    detail:
      "Installs packages while the skill runs. Each install is an arbitrary-code-execution path and makes the skill non-reproducible.",
    severity: "medium",
    scope: "code",
    capability: "install",
    pattern:
      /\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add|dlx|exec)\b|\bpip3?\s+install\b|\buv\s+(?:pip\s+install|tool\s+install|add)\b|\buvx\b|\bpipx\b|\b(?:brew|apt-get|apt|yum|dnf|pacman|apk|choco|winget|snap)\s+(?:install|add)\b|\bcargo\s+install\b|\bgo\s+install\b|\bgem\s+install\b|\bnpx\b/,
  },
  {
    id: "R015",
    title: "Launches another agent",
    detail:
      "Spawns a further agent or sub-agent. This expands what can run beyond what the reviewer can see in this skill alone.",
    severity: "medium",
    scope: "code",
    capability: "agent.spawn",
    pattern:
      /\b(?:claude|codex|opencode|gemini|aider|goose|crush)\b[^\n]*(?:--print|--exec|\s-p\s)|\bsubagent\b|\bspawn_agent\b|\bTask\s*\(\s*\{/,
  },
  // ------------------------------------- capability signals (no finding noise)
  {
    id: "R012",
    title: "Shell execution",
    detail: "Runs shell commands or spawns child processes.",
    severity: "info",
    scope: "any",
    capability: "exec",
    capabilityOnly: true,
    pattern:
      /`(?:bash|sh|zsh|fish|pwsh|powershell|cmd)\s+-[a-zA-Z]*c\b|\bchild_process\b|\bexecSync\b|\bspawnSync\b|\bsubprocess\b|\bos\.system\b|!`[^`\n]+`/,
  },
  {
    id: "R013",
    title: "Network access",
    detail: "Makes outbound network requests.",
    severity: "info",
    scope: "code",
    capability: "network",
    capabilityOnly: true,
    pattern: new RegExp(
      String.raw`\b(?:${NET_BIN})\b|\bfetch\s*\(|\baxios\b|\brequests\.(?:get|post|put|delete|patch)\b|\burllib\b|\bhttpx\b|\bnet\/http\b|\bhttp\.request\b|\bhttps?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)`,
    ),
  },
  {
    id: "R014",
    title: "MCP server usage",
    detail: "Declares or launches an MCP server.",
    severity: "info",
    scope: "any",
    capability: "mcp",
    capabilityOnly: true,
    pattern: /mcpServers|\.mcp\.json\b|\bmcp\.json\b|modelcontextprotocol|mcp-server|mcp_server|@[\w-]*mcp\b/,
  },
  {
    id: "R018",
    title: "File reads",
    detail: "Reads file contents.",
    severity: "info",
    scope: "any",
    capability: "fs.read",
    capabilityOnly: true,
    pattern: /\breadFileSync\b|\breadFile\s*\(|\bcat\s+\S|\bopen\s*\([^)]*['"]r|\bGet-Content\b/,
  },
  {
    id: "R019",
    title: "File writes",
    detail: "Writes or moves files.",
    severity: "info",
    scope: "any",
    capability: "fs.write",
    capabilityOnly: true,
    pattern:
      /\bwriteFileSync\b|\bwriteFile\s*\(|\bmkdirSync\b|\bshutil\.(?:copy|move|rmtree)\b|\b(?:cp|mv|mkdir|touch|tee)\s+\S|>{1,2}\s*\S/,
  },
];

/** Tools from `allowed-tools` that map onto capabilities. */
export const TOOL_CAPABILITY_MAP: Array<{ match: RegExp; capability: CapabilityId }> = [
  { match: /^bash/i, capability: "exec" },
  { match: /^(?:write|edit|multiedit|notebookedit|strreplace)/i, capability: "fs.write" },
  { match: /^read/i, capability: "fs.read" },
  { match: /^(?:webfetch|websearch|fetch|browser)/i, capability: "network" },
  { match: /^(?:task|agent|subagent)/i, capability: "agent.spawn" },
  { match: /^mcp/i, capability: "mcp" },
];

/**
 * Capabilities that must never be silently inferred: if a skill exercises one
 * of these but does not declare it, that is worth failing CI over.
 */
export const SIGNIFICANT_CAPABILITIES: readonly CapabilityId[] = [
  "exec",
  "network",
  "secrets",
  "destructive",
  "fs.write",
  "install",
  "privilege",
  "agent.spawn",
] as const;
