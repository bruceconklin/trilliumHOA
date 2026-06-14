const SUPER_ADMIN = 'me@bruceconklin.com';

function isAdmin(email, members) {
  if (email.toLowerCase() === SUPER_ADMIN.toLowerCase()) return true;
  const member = members.find(m => m.email.toLowerCase() === email.toLowerCase());
  return !!(member && member.is_admin);
}

export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() });
  }

  const email = request.headers.get('Cf-Access-Authenticated-User-Email') || '';
  const members = JSON.parse(await env.HOA_DATA.get('members') || '[]');

  if (!isAdmin(email, members)) {
    return json({ error: 'Unauthorized' }, 403);
  }

  if (request.method === 'GET') {
    const budget = await env.HOA_DATA.get('budget') || '[]';
    return new Response(budget, { headers: { 'Content-Type': 'application/json' } });
  }

  if (request.method === 'PUT') {
    const body = await request.json();
    await env.HOA_DATA.put('budget', JSON.stringify(body));
    return json({ ok: true });
  }

  return json({ error: 'Method not allowed' }, 405);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}
