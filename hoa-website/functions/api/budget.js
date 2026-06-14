export async function onRequest({ request, env }) {
  const email = request.headers.get('Cf-Access-Authenticated-User-Email') || '';
  if (!email) return json({ error: 'Not authenticated' }, 401);

  const budget = JSON.parse(await env.HOA_DATA.get('budget') || '[]');
  return json(budget);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
