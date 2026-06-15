// Trillium Lane HOA — Cloudflare Worker
// Handles all /api/* routes; static assets (HTML, CSS, etc.) are served automatically.

const SUPER_ADMIN = 'me@bruceconklin.com';

const PRICE_MONTHLY = 'price_1TaN7r2NsbOSaiK9BQjhidGr';
const PRICE_YEARLY  = 'price_1TaN7r2NsbOSaiK9A2lsODMZ';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function getEmail(request) {
  return (request.headers.get('Cf-Access-Authenticated-User-Email') || '').toLowerCase();
}

function isAdmin(email, members) {
  if (email === SUPER_ADMIN.toLowerCase()) return true;
  const m = members.find(m => m.email.toLowerCase() === email);
  return !!(m && m.is_admin);
}

async function getMembers(env) {
  return JSON.parse(await env.HOA_DATA.get('members') || '[]');
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

// GET /api/me
async function handleMe(request, env) {
  const email = getEmail(request);
  if (!email) return json({ error: 'Not authenticated' }, 401);
  const members = await getMembers(env);
  const m = members.find(m => m.email.toLowerCase() === email);
  if (!m) return json({ error: 'Member not found' }, 404);
  return json({
    name: m.name,
    email: m.email,
    address: m.address || '',
    phone: m.phone || '',
    payment_status: m.payment_status,
    payment_method: m.payment_method,
    is_admin: m.is_admin === true,
  });
}

// PATCH /api/profile
async function handleProfile(request, env) {
  if (request.method !== 'PATCH') return json({ error: 'Method not allowed' }, 405);
  const email = getEmail(request);
  if (!email) return json({ error: 'Not authenticated' }, 401);
  const members = await getMembers(env);
  const idx = members.findIndex(m => m.email.toLowerCase() === email);
  if (idx === -1) return json({ error: 'Member not found' }, 404);
  const body = await request.json();
  ['name', 'address', 'phone'].forEach(field => {
    if (body[field] !== undefined) members[idx][field] = String(body[field]).trim();
  });
  await env.HOA_DATA.put('members', JSON.stringify(members));
  return json({ ok: true, name: members[idx].name, address: members[idx].address, phone: members[idx].phone });
}

// GET /api/members — directory (no payment info)
async function handleMembers(request, env) {
  const email = getEmail(request);
  if (!email) return json({ error: 'Not authenticated' }, 401);
  const members = await getMembers(env);
  return json(members.map(m => ({
    name: m.name,
    email: m.email,
    address: m.address || '',
    phone: m.phone || '',
  })));
}

// GET /api/newsletters
async function handleNewsletters(request, env) {
  const email = getEmail(request);
  if (!email) return json({ error: 'Not authenticated' }, 401);
  const data = await env.HOA_DATA.get('newsletters') || '[]';
  return new Response(data, { headers: { 'Content-Type': 'application/json' } });
}

// GET /api/budget
async function handleBudget(request, env) {
  const email = getEmail(request);
  if (!email) return json({ error: 'Not authenticated' }, 401);
  const data = await env.HOA_DATA.get('budget') || '[]';
  return new Response(data, { headers: { 'Content-Type': 'application/json' } });
}

// GET/PUT /api/admin/members
async function handleAdminMembers(request, env) {
  const email = getEmail(request);
  const members = await getMembers(env);
  if (!isAdmin(email, members)) return json({ error: 'Unauthorized' }, 403);
  if (request.method === 'GET') {
    return json(members);
  }
  if (request.method === 'PUT') {
    const body = await request.json();
    await env.HOA_DATA.put('members', JSON.stringify(body));
    return json({ ok: true });
  }
  return json({ error: 'Method not allowed' }, 405);
}

// GET/PUT /api/admin/newsletters
async function handleAdminNewsletters(request, env) {
  const email = getEmail(request);
  const members = await getMembers(env);
  if (!isAdmin(email, members)) return json({ error: 'Unauthorized' }, 403);
  if (request.method === 'GET') {
    const data = await env.HOA_DATA.get('newsletters') || '[]';
    return new Response(data, { headers: { 'Content-Type': 'application/json' } });
  }
  if (request.method === 'PUT') {
    const body = await request.json();
    await env.HOA_DATA.put('newsletters', JSON.stringify(body));
    return json({ ok: true });
  }
  return json({ error: 'Method not allowed' }, 405);
}

// GET/PUT /api/admin/budget
async function handleAdminBudget(request, env) {
  const email = getEmail(request);
  const members = await getMembers(env);
  if (!isAdmin(email, members)) return json({ error: 'Unauthorized' }, 403);
  if (request.method === 'GET') {
    const data = await env.HOA_DATA.get('budget') || '[]';
    return new Response(data, { headers: { 'Content-Type': 'application/json' } });
  }
  if (request.method === 'PUT') {
    const body = await request.json();
    await env.HOA_DATA.put('budget', JSON.stringify(body));
    return json({ ok: true });
  }
  return json({ error: 'Method not allowed' }, 405);
}

// POST /api/stripe-webhook
async function handleStripeWebhook(request, env) {
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

  const rawBody = await request.text();
  const sigHeader = request.headers.get('Stripe-Signature') || '';

  if (!env.STRIPE_WEBHOOK_SECRET) {
    console.error('STRIPE_WEBHOOK_SECRET not set');
    return json({ error: 'Server misconfiguration' }, 500);
  }

  // Verify Stripe signature
  const parts = Object.fromEntries(sigHeader.split(',').map(p => p.split('=')));
  const timestamp = parts.t;
  const receivedSig = parts.v1;
  if (!timestamp || !receivedSig) return json({ error: 'Invalid signature header' }, 400);

  const age = Math.floor(Date.now() / 1000) - parseInt(timestamp);
  if (age > 300) return json({ error: 'Timestamp too old' }, 400);

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(env.STRIPE_WEBHOOK_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBytes = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${rawBody}`));
  const computedSig = Array.from(new Uint8Array(sigBytes)).map(b => b.toString(16).padStart(2, '0')).join('');
  if (computedSig !== receivedSig) return json({ error: 'Invalid signature' }, 400);

  const event = JSON.parse(rawBody);
  const members = await getMembers(env);

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      if (session.mode !== 'subscription') break;
      const email = session.customer_details?.email?.toLowerCase();
      if (!email) break;
      const amount = session.amount_total;
      const paymentMethod = amount === 24000 ? 'autopay_annual' : 'autopay_monthly';
      const idx = members.findIndex(m => m.email.toLowerCase() === email);
      if (idx !== -1) {
        members[idx].payment_status = 'current';
        members[idx].payment_method = paymentMethod;
      } else {
        members.push({
          name: session.customer_details?.name || '',
          email,
          address: '',
          phone: '',
          payment_status: 'current',
          payment_method: paymentMethod,
          is_admin: false,
        });
      }
      await env.HOA_DATA.put('members', JSON.stringify(members));
      break;
    }
    case 'invoice.payment_succeeded': {
      const invoice = event.data.object;
      if (!invoice.subscription) break;
      const email = invoice.customer_email?.toLowerCase();
      if (!email) break;
      const priceId = invoice.lines?.data?.[0]?.price?.id;
      const idx = members.findIndex(m => m.email.toLowerCase() === email);
      if (idx !== -1) {
        members[idx].payment_status = 'current';
        if (priceId === PRICE_MONTHLY) members[idx].payment_method = 'autopay_monthly';
        if (priceId === PRICE_YEARLY)  members[idx].payment_method = 'autopay_annual';
        await env.HOA_DATA.put('members', JSON.stringify(members));
      }
      break;
    }
    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      if (!invoice.subscription) break;
      const email = invoice.customer_email?.toLowerCase();
      if (!email) break;
      const idx = members.findIndex(m => m.email.toLowerCase() === email);
      if (idx !== -1) {
        members[idx].payment_status = 'past_due';
        await env.HOA_DATA.put('members', JSON.stringify(members));
      }
      break;
    }
    default:
      console.log(`Unhandled Stripe event: ${event.type}`);
  }

  return json({ received: true });
}

// ---------------------------------------------------------------------------
// Main fetch handler — route /api/* or fall through to static assets
// ---------------------------------------------------------------------------
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith('/api/')) {
      if (path === '/api/me')                   return handleMe(request, env);
      if (path === '/api/profile')              return handleProfile(request, env);
      if (path === '/api/members')              return handleMembers(request, env);
      if (path === '/api/newsletters')          return handleNewsletters(request, env);
      if (path === '/api/budget')               return handleBudget(request, env);
      if (path === '/api/admin/members')        return handleAdminMembers(request, env);
      if (path === '/api/admin/newsletters')    return handleAdminNewsletters(request, env);
      if (path === '/api/admin/budget')         return handleAdminBudget(request, env);
      if (path === '/api/stripe-webhook')       return handleStripeWebhook(request, env);
      return json({ error: 'Not found' }, 404);
    }

    // All other requests → serve static assets (HTML, CSS, images, etc.)
    return env.ASSETS.fetch(request);
  },
};
