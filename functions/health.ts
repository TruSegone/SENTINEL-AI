import { proxyRequest } from './_proxy';

export const onRequest = ({ request, env }: { request: Request; env: { SENTINEL_API_ORIGIN?: string } }) =>
  proxyRequest(request, env);
