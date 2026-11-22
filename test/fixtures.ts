import { MockHttpClient } from "./mockClient.js";

export const BASE = "https://demo-app.example";
export const SUPABASE = "https://abcdefghijklmnopqrst.supabase.co";

function fakeJwt(role: string): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "HS256", typ: "JWT" }),
  ).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({ role, iss: "supabase-demo", ref: "FAKEFAKEFAKE" }),
  ).toString("base64url");
  return `${header}.${payload}.FAKE_SIGNATURE_NOT_REAL_000000000000`;
}

export const FAKE_ANON_JWT = fakeJwt("anon");
export const FAKE_SERVICE_JWT = fakeJwt("service_role");
export const FAKE_SB_PUBLISHABLE = "sb_publishable_FAKEstackauditEXAMPLE000";
export const FAKE_SB_SECRET = "sb_secret_FAKEstackauditEXAMPLE000000";
export const FAKE_STRIPE = ["sk", "live", "FAKE000stackauditEXAMPLE000"].join("_");
export const FAKE_AWS = "AKIAFAKEEXAMPLE00000";

export function vulnerableBundle(): string {
  return [
    `const SUPABASE_URL = "${SUPABASE}";`,
    `const SUPABASE_ANON = "${FAKE_ANON_JWT}";`,
    `const SERVICE_KEY = "${FAKE_SERVICE_JWT}";`,
    `const NEW_SECRET = "${FAKE_SB_SECRET}";`,
    `const NEW_PUB = "${FAKE_SB_PUBLISHABLE}";`,
    `const STRIPE = "${FAKE_STRIPE}";`,
    `const AWS = "${FAKE_AWS}";`,
    `supabase.from('users').select('*');`,
    `supabase.from('products').select('*');`,
    `supabase.storage.from('avatars').list();`,
    `supabase.rpc('promote_to_admin');`,
    `//# sourceMappingURL=app.js.map`,
  ].join("\n");
}

export function vulnerableClient(): MockHttpClient {
  const client = new MockHttpClient();
  client.on("GET", `${BASE}/`, {
    status: 200,
    headers: { "x-vercel-id": "gru1::abc", server: "Vercel" },
    body: `<!doctype html><html><head><script src="/assets/app.js"></script></head><body></body></html>`,
  });
  client.on("GET", `${BASE}/assets/app.js`, {
    status: 200,
    headers: {},
    body: vulnerableBundle(),
  });
  client.on("GET", `${BASE}/assets/app.js.map`, {
    status: 200,
    headers: {},
    body: `{"version":3,"sources":["src/App.tsx"],"mappings":"AAAA"}`,
  });
  client.on("GET", `${BASE}/.env`, {
    status: 200,
    headers: {},
    body: `DATABASE_URL=postgres://fake\nSTRIPE_KEY=${FAKE_STRIPE}\n`,
  });
  client.on("GET", `${BASE}/.git/config`, {
    status: 200,
    headers: {},
    body: `[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@example.com:demo/app.git\n`,
  });
  client.on("GET", `${BASE}/.git/HEAD`, {
    status: 200,
    headers: {},
    body: `ref: refs/heads/main\n`,
  });

  client.on("HEAD", `${SUPABASE}/rest/v1/users?select=*`, {
    status: 200,
    headers: { "content-range": "0-0/1452" },
  });
  client.on("HEAD", `${SUPABASE}/rest/v1/products?select=*`, {
    status: 200,
    headers: { "content-range": "0-0/320" },
  });
  client.on("POST", `${SUPABASE}/storage/v1/object/list/avatars`, {
    status: 200,
    headers: {},
    body: `[{"name":"1.png"},{"name":"2.png"}]`,
  });
  client.on("GET", `${SUPABASE}/auth/v1/settings`, {
    status: 200,
    headers: {},
    body: `{"disable_signup":false,"mailer_autoconfirm":true}`,
  });
  client.on("HEAD", `${SUPABASE}/graphql/v1`, {
    status: 200,
    headers: {},
  });
  return client;
}

export function cleanClient(): MockHttpClient {
  const client = new MockHttpClient();
  client.on("GET", `${BASE}/`, {
    status: 200,
    headers: {
      "x-vercel-id": "gru1::xyz",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "strict-transport-security": "max-age=63072000",
      "referrer-policy": "no-referrer",
    },
    body: `<!doctype html><html><head><script src="/assets/clean.js"></script></head><body></body></html>`,
  });
  client.on("GET", `${BASE}/assets/clean.js`, {
    status: 200,
    headers: {},
    body: `console.log("no secrets here");`,
  });
  return client;
}
