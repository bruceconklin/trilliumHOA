export async function onRequest({ request, env }) {
  const email = request.headers.get('Cf-Access-Authenticated-User-Email') || '';
  if (!email) return json({ error: 'Not authenticated' }, 401);

  const members = JSON.parse(await env.HOA_DATA.get('members') || '[]');
  const member = members.find(m => m.email.toLowerCase() === email.toLowerCase());

  if (!member) return json({ error: 'Member not found' }, 404);

  return json({
    name: member.name,
    email: member.email,
    address: member.address || '',
    phone: member.phone || '',
    payment_status: member.payment_status,
    payment_method: member.payment_method,
    is_admin: member.is_admin === true,
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
