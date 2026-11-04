// Cloudflare Pages Function: POST /api/reveal
// Verifies a Turnstile token with Cloudflare, then returns the contact email.
// Required environment variables (Pages project > Settings > Variables and Secrets):
//   TURNSTILE_SECRET  the Turnstile widget's secret key
//   CONTACT_EMAIL     the address to reveal

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

export async function onRequestPost({ request, env }) {
  if (!env.TURNSTILE_SECRET || !env.CONTACT_EMAIL) return json({ ok: false, error: "not-configured" }, 500);

  // Only accept requests that come from this site.
  const origin = request.headers.get("Origin");
  if (origin && new URL(origin).host !== new URL(request.url).host) return json({ ok: false, error: "origin" }, 403);

  let token;
  try {
    ({ token } = await request.json());
  } catch {
    return json({ ok: false, error: "bad-request" }, 400);
  }
  if (typeof token !== "string" || !token || token.length > 2048) return json({ ok: false, error: "bad-request" }, 400);

  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET);
  form.append("response", token);
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) form.append("remoteip", ip);

  let result;
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
    result = await res.json();
  } catch {
    return json({ ok: false, error: "verify-failed" }, 502);
  }
  if (!result.success) return json({ ok: false, error: "check-failed" }, 403);

  return json({ ok: true, email: env.CONTACT_EMAIL });
}

export const onRequest = () => json({ ok: false, error: "method" }, 405);
