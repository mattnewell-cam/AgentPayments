import type { Context } from "https://edge.netlify.com";

const BOT_PATTERNS = [
  /GPTBot/i,
  /ChatGPT-User/i,
  /Claude-Web/i,
  /Anthropic/i,
  /CCBot/i,
  /Google-Extended/i,
  /Bytespider/i,
  /Amazonbot/i,
  /FacebookBot/i,
  /Applebot-Extended/i,
  /PerplexityBot/i,
  /YouBot/i,
];

function isBot(userAgent: string): boolean {
  return BOT_PATTERNS.some((pattern) => pattern.test(userAgent));
}

function isPublicPath(pathname: string): boolean {
  if (pathname === "/robots.txt") return true;
  if (pathname.startsWith("/.well-known/")) return true;
  return false;
}

export default async function gate(request: Request, context: Context) {
  const url = new URL(request.url);

  // Always allow public endpoints
  if (isPublicPath(url.pathname)) {
    return context.next();
  }

  const userAgent = request.headers.get("user-agent") || "";

  // Non-bot traffic passes through
  if (!isBot(userAgent)) {
    return context.next();
  }

  // Bot detected — check for valid key
  const agentKey = request.headers.get("X-Agent-Key");

  if (!agentKey) {
    return new Response(
      JSON.stringify({
        error: "forbidden",
        message:
          "AI agent access requires a valid API key. Send it via the X-Agent-Key header.",
        details: "GET /.well-known/agent-access.json for instructions.",
      }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      },
    );
  }

  // Validate against allowed keys from env var
  const allowedKeysRaw = Deno.env.get("ALLOWED_KEYS") || "";
  const allowedKeys = allowedKeysRaw
    .split(",")
    .map((k) => k.trim())
    .filter(Boolean);

  if (!allowedKeys.includes(agentKey)) {
    return new Response(
      JSON.stringify({
        error: "forbidden",
        message: "Invalid API key.",
        details: "GET /.well-known/agent-access.json for instructions.",
      }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      },
    );
  }

  // Valid key — log and pass through
  console.log(
    `[gate] Authenticated agent access: key=${agentKey.slice(0, 8)}... ip=${context.ip} path=${url.pathname}`,
  );

  return context.next();
}
