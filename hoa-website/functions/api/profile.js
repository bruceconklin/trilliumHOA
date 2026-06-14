// Allows a member to update their own name, address, and phone.
// Email is intentionally not editable — it is the Cloudflare Access login identity.

export async function onRequest({ request, env }) {
  if (request.method !== 'PATCH') return json({ error: 'Method not allowed' }, 405);

  const email = request.headers.get('Cf-Access-Authenticated-User-Email') || '';
  if (!email) return json({ error: 'Not authenticated' }, 401);

  const members = JSON.parse(await env.HOA_DATA.get('members') || '[]');
  const idx = members.findIndex(m => m.email.toLowerCase() === email.toLowerCase());

  if (idx === -1) return json({ error: 'Member not found' }, 404);

  const body = await request.json();

  // Only allow these fields to be self-edited
  const editable = ['name', 'address', 'phone'];
  editable.forEach(field => {
    if (body[field] !== undefined) {
      members[idx][field] = String(body[field]).trim();
    }
  });

  await env.HOA_DATA.put('members', JSON.stringify(members));

  return json({
    ok: true,
    name: members[idx].name,
    address: members[idx].address,
    phone: members[idx].phone,
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
