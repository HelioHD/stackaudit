export function redact(secret: string): string {
  if (secret.length <= 10) return `${secret.slice(0, 2)}***`;
  return `${secret.slice(0, 6)}...${secret.slice(-4)}`;
}

export interface SupabaseKey {
  format: "legacy-jwt" | "sb-secret" | "sb-publishable";
  role: string | null;
  isSecret: boolean;
  redacted: string;
  raw: string;
}

function decodeBase64Url(segment: string): string | null {
  try {
    return Buffer.from(segment, "base64url").toString("utf8");
  } catch {
    return null;
  }
}

export function inspectSupabaseKeys(content: string): SupabaseKey[] {
  const out: SupabaseKey[] = [];
  const seen = new Set<string>();

  const prefixed = content.matchAll(
    /\b(sb_(?:secret|publishable)_[A-Za-z0-9_-]{10,})\b/g,
  );
  for (const m of prefixed) {
    const value = m[1]!;
    if (seen.has(value)) continue;
    seen.add(value);
    const isSecret = value.startsWith("sb_secret_");
    out.push({
      format: isSecret ? "sb-secret" : "sb-publishable",
      role: isSecret ? "service_role" : "anon",
      isSecret,
      redacted: redact(value),
      raw: value,
    });
  }

  const jwts = content.matchAll(
    /\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}\b/g,
  );
  for (const m of jwts) {
    const token = m[0];
    const payloadSegment = m[1]!;
    if (seen.has(token)) continue;
    const decoded = decodeBase64Url(payloadSegment);
    if (!decoded) continue;
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(decoded) as Record<string, unknown>;
    } catch {
      continue;
    }
    const role = typeof payload.role === "string" ? payload.role : null;
    const iss = typeof payload.iss === "string" ? payload.iss : "";
    const looksSupabase = role === "anon" || role === "service_role" ||
      iss.includes("supabase");
    if (!looksSupabase) continue;
    seen.add(token);
    out.push({
      format: "legacy-jwt",
      role,
      isSecret: role === "service_role",
      redacted: redact(token),
      raw: token,
    });
  }

  return out;
}
