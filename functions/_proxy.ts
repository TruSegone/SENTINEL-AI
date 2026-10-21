interface Env {
  SENTINEL_API_ORIGIN?: string;
}

export async function proxyRequest(request: Request, env: Env): Promise<Response> {
  const configuredOrigin = env.SENTINEL_API_ORIGIN;
  if (!configuredOrigin) {
    return Response.json(
      {
        detail: {
          code: 'api_origin_not_configured',
          message: 'Set SENTINEL_API_ORIGIN in the Cloudflare Pages Functions variables.',
        },
      },
      { status: 503 },
    );
  }

  let origin: URL;
  try {
    origin = new URL(configuredOrigin);
  } catch {
    return Response.json(
      { detail: { code: 'invalid_api_origin', message: 'SENTINEL_API_ORIGIN must be a valid HTTPS origin.' } },
      { status: 500 },
    );
  }

  const localDevelopment = origin.hostname === 'localhost' || origin.hostname === '127.0.0.1';
  if ((origin.protocol !== 'https:' && !localDevelopment) || origin.username || origin.password || origin.pathname !== '/') {
    return Response.json(
      { detail: { code: 'invalid_api_origin', message: 'SENTINEL_API_ORIGIN must be an HTTPS origin without credentials or a path.' } },
      { status: 500 },
    );
  }

  const incoming = new URL(request.url);
  const target = new URL(`${incoming.pathname}${incoming.search}`, origin);
  try {
    return await fetch(new Request(target, request));
  } catch {
    return Response.json(
      { detail: { code: 'api_unavailable', message: 'The Sentinel API could not be reached. It may be starting from an idle state.' } },
      { status: 502 },
    );
  }
}
