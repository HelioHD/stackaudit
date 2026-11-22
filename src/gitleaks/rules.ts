/**
 * Subset of gitleaks' open-source detection rules.
 * Source: gitleaks config `config/gitleaks.toml` at tag v8.21.2
 * (https://github.com/gitleaks/gitleaks), MIT licensed.
 * Regexes copied verbatim; only a curated subset is vendored so the tool
 * needs neither the gitleaks binary nor a network fetch. See README.
 */
export interface GitleaksRule {
  id: string;
  description: string;
  regex: RegExp;
  keywords: string[];
}

export const GITLEAKS_VERSION = "8.21.2";

export const gitleaksRules: GitleaksRule[] = [
  {
    id: "aws-access-token",
    description: "AWS Access Key",
    regex: /\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b/,
    keywords: ["akia", "asia", "abia", "acca", "a3t"],
  },
  {
    id: "github-pat",
    description: "GitHub Personal Access Token",
    regex: /\bghp_[0-9a-zA-Z]{36}\b/,
    keywords: ["ghp_"],
  },
  {
    id: "github-fine-grained-pat",
    description: "GitHub Fine-Grained Personal Access Token",
    regex: /\bgithub_pat_[0-9a-zA-Z_]{82}\b/,
    keywords: ["github_pat_"],
  },
  {
    id: "stripe-access-token",
    description: "Stripe Access Token",
    regex: /\b(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{10,99}\b/,
    keywords: ["sk_test", "sk_live", "rk_test", "rk_live"],
  },
  {
    id: "slack-bot-token",
    description: "Slack Bot Token",
    regex: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{23,34}\b/,
    keywords: ["xoxb-"],
  },
  {
    id: "slack-webhook-url",
    description: "Slack Webhook",
    regex:
      /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+/]{43,56}/,
    keywords: ["hooks.slack.com"],
  },
  {
    id: "google-api-key",
    description: "Google API Key",
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/,
    keywords: ["aiza"],
  },
  {
    id: "sendgrid-api-token",
    description: "SendGrid API Token",
    regex: /\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/,
    keywords: ["sg."],
  },
  {
    id: "openai-api-key",
    description: "OpenAI API Key",
    regex: /\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b/,
    keywords: ["t3blbkfj"],
  },
  {
    id: "jwt",
    description: "JSON Web Token",
    regex:
      /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    keywords: ["eyj"],
  },
  {
    id: "private-key",
    description: "Private Key",
    regex:
      /-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----/,
    keywords: ["-----begin"],
  },
  {
    id: "twilio-api-key",
    description: "Twilio API Key",
    regex: /\bSK[0-9a-fA-F]{32}\b/,
    keywords: ["sk"],
  },
];

export interface SecretMatch {
  ruleId: string;
  description: string;
  match: string;
}

export function scanWithGitleaks(content: string): SecretMatch[] {
  const lower = content.toLowerCase();
  const out: SecretMatch[] = [];
  const seen = new Set<string>();
  for (const rule of gitleaksRules) {
    if (!rule.keywords.some((k) => lower.includes(k))) continue;
    const re = new RegExp(rule.regex.source, "g");
    for (const m of content.matchAll(re)) {
      const value = m[0];
      const key = `${rule.id}:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ ruleId: rule.id, description: rule.description, match: value });
    }
  }
  return out;
}
