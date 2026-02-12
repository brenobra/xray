export function securityHeaders(): HeadersInit {
  return {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com; style-src 'unsafe-inline' https://cdn.tailwindcss.com; connect-src 'self'; img-src 'self' data:; font-src 'self'",
  };
}

export function corsHeaders(origin: string): HeadersInit {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    ...securityHeaders(),
  };
}

export function jsonResponse(
  data: unknown,
  origin: string,
  status = 200
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(origin),
    },
  });
}
