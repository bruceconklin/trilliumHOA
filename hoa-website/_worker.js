// Trillium Lane HOA — Cloudflare Worker
// Self-hosted email OTP authentication via Resend.
//
// Environment variables (set in Cloudflare Pages → Settings → Environment Variables):
//   RESEND_API_KEY        — from resend.com dashboard
//   STRIPE_WEBHOOK_SECRET — from Stripe Dashboard → Developers → Webhooks
//   STRIPE_SECRET_KEY     — from Stripe Dashboard → Developers → API keys (secret key)

const SUPER_ADMIN    = 'me@bruceconklin.com';
const HOA_FROM_EMAIL = 'Trillium Lane HOA <noreply@trilliumlane.org>';
const SESSION_COOKIE = 'hoa_session';
const SESSION_TTL    = 60 * 60 * 24 * 60;  // 60 days in seconds
const OTP_TTL        = 60 * 10;             // 10 minutes in seconds

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

function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  const match = header.split(';').map(c => c.trim()).find(c => c.startsWith(name + '='));
  return match ? match.slice(name.length + 1) : null;
}

async function getEmailFromSession(request, env) {
  const sessionId = getCookie(request, SESSION_COOKIE);
  if (!sessionId) return null;
  const stored = await env.HOA_DATA.get(`session:${sessionId}`);
  if (!stored) return null;
  try { return JSON.parse(stored).email || null; }
  catch { return null; }
}

function isAdmin(email, members) {
  if (email === SUPER_ADMIN.toLowerCase()) return true;
  // Primary account
  const primary = members.find(m => m.email.toLowerCase() === email);
  if (primary && primary.is_admin) return true;
  // Spouse has independent admin flag — does NOT inherit from primary
  const household = members.find(m => m.spouse_email && m.spouse_email.toLowerCase() === email);
  if (household && household.spouse_is_admin) return true;
  return false;
}

// Find the household record for a given email (primary or spouse login)
function findHousehold(members, email) {
  let idx = members.findIndex(m => m.email.toLowerCase() === email);
  if (idx !== -1) return { idx, isSpouse: false };
  idx = members.findIndex(m => m.spouse_email && m.spouse_email.toLowerCase() === email);
  if (idx !== -1) return { idx, isSpouse: true };
  return null;
}

async function getMembers(env) {
  return JSON.parse(await env.HOA_DATA.get('members') || '[]');
}

function loginRedirect(path) {
  return Response.redirect(`/members/login/?redirect=${encodeURIComponent(path)}`, 302);
}

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

// POST /api/auth/request-otp
async function handleRequestOTP(request, env) {
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
  const { email } = await request.json();
  if (!email) return json({ error: 'Email required' }, 400);

  const normalEmail = email.toLowerCase().trim();
  const members = await getMembers(env);

  // Find by primary email first, then spouse email
  let member = members.find(m => m.email.toLowerCase() === normalEmail);
  let isSpouse = false;
  if (!member) {
    member = members.find(m => m.spouse_email && m.spouse_email.toLowerCase() === normalEmail);
    if (member) isSpouse = true;
  }

  // Also allow superadmin even if not in members list
  if (!member && normalEmail !== SUPER_ADMIN.toLowerCase()) {
    return json({ error: 'Email not found. Contact hoa@trilliumlane.org to be added as a member.' }, 404);
  }

  const name = isSpouse ? (member?.spouse_name || 'there') : (member?.name || 'there');
  const code = String(Math.floor(100000 + Math.random() * 900000));

  // Store OTP in KV (10 min TTL)
  await env.HOA_DATA.put(
    `otp:${normalEmail}`,
    JSON.stringify({ code }),
    { expirationTtl: OTP_TTL }
  );

  // Send email via Resend
  const emailRes = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: HOA_FROM_EMAIL,
      to: email,
      subject: 'Your Trillium Lane HOA login code',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;color:#2c2c2c">
          <div style="background:#2d5a3d;padding:1.5rem;text-align:center">
            <h1 style="color:#fff;font-size:1.2rem;margin:0">Trillium Lane HOA</h1>
          </div>
          <div style="padding:2rem;background:#fff;border:1px solid #d4e6da">
            <p>Hi ${name},</p>
            <p>Your one-time login code for the member portal is:</p>
            <div style="text-align:center;margin:2rem 0">
              <span style="font-size:2.5rem;font-weight:bold;letter-spacing:0.4em;color:#1e3f2b">${code}</span>
            </div>
            <p style="color:#666;font-size:0.9rem">This code expires in 10 minutes. If you didn't request this, you can safely ignore this email.</p>
          </div>
          <p style="text-align:center;color:#999;font-size:0.75rem;padding:1rem">Trillium Lane HOA &middot; Mill Valley, CA</p>
        </div>
      `,
    }),
  });

  if (!emailRes.ok) {
    const err = await emailRes.text();
    console.error('Resend error:', err);
    return json({ error: 'Failed to send email. Please try again.' }, 500);
  }

  return json({ ok: true });
}

// POST /api/auth/verify-otp
async function handleVerifyOTP(request, env) {
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
  const { email, code } = await request.json();
  if (!email || !code) return json({ error: 'Email and code required' }, 400);

  const normalEmail = email.toLowerCase().trim();
  const stored = await env.HOA_DATA.get(`otp:${normalEmail}`);
  if (!stored) return json({ error: 'Code expired or not found. Please request a new one.' }, 400);

  const { code: storedCode } = JSON.parse(stored);
  if (code.trim() !== storedCode) return json({ error: 'Incorrect code. Please try again.' }, 400);

  // Delete OTP — one-time use only
  await env.HOA_DATA.delete(`otp:${normalEmail}`);

  // Create session
  const sessionId = crypto.randomUUID();
  await env.HOA_DATA.put(
    `session:${sessionId}`,
    JSON.stringify({ email: normalEmail, created: Date.now() }),
    { expirationTtl: SESSION_TTL }
  );

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': `${SESSION_COOKIE}=${sessionId}; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}; Path=/`,
    },
  });
}

// POST /api/auth/logout
async function handleLogout(request, env) {
  const sessionId = getCookie(request, SESSION_COOKIE);
  if (sessionId) await env.HOA_DATA.delete(`session:${sessionId}`);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/`,
    },
  });
}

// ---------------------------------------------------------------------------
// Protected API handlers
// ---------------------------------------------------------------------------

// GET /api/me
async function handleMe(request, env, email) {
  const members = await getMembers(env);
  const found = findHousehold(members, email);
  if (!found) {
    if (email === SUPER_ADMIN.toLowerCase()) {
      return json({ name: 'Bruce Conklin', email, address: '', phone: '', payment_status: 'current', payment_method: 'check', is_admin: true, show_in_directory: false, is_spouse: false, spouse_name: '', spouse_email: '' });
    }
    return json({ error: 'Member not found' }, 404);
  }
  const { idx, isSpouse } = found;
  const m = members[idx];
  return json({
    name: isSpouse ? (m.spouse_name || m.name) : m.name,
    email,
    address: m.address || '',
    phone: m.phone || '',
    payment_status: m.payment_status,
    payment_method: m.payment_method,
    is_admin: isSpouse
      ? (m.spouse_is_admin === true)
      : (m.is_admin === true || email === SUPER_ADMIN.toLowerCase()),
    // For spouse login, show_in_directory reflects their own directory pref
    show_in_directory: isSpouse ? (m.spouse_show_in_directory === true) : (m.show_in_directory === true),
    is_spouse: isSpouse,
    // Only expose spouse fields to the primary account holder
    spouse_name: isSpouse ? undefined : (m.spouse_name || ''),
    spouse_email: isSpouse ? undefined : (m.spouse_email || ''),
    spouse_phone: isSpouse ? undefined : (m.spouse_phone || ''),
    spouse_show_in_directory: isSpouse ? undefined : (m.spouse_show_in_directory === true),
    // email_updates: undefined/true = subscribed, false = opted out
    email_updates: isSpouse ? (m.spouse_email_updates !== false) : (m.email_updates !== false),
    // stripe_email is never exposed to the client
  });
}

// PATCH /api/profile
async function handleProfile(request, env, email) {
  if (request.method !== 'PATCH') return json({ error: 'Method not allowed' }, 405);
  const members = await getMembers(env);
  const found = findHousehold(members, email);
  if (!found) return json({ error: 'Member not found' }, 404);
  const { idx, isSpouse } = found;
  const body = await request.json();

  // "name" always refers to the logged-in person's own display name
  if (body.name !== undefined) {
    if (isSpouse) {
      members[idx].spouse_name = String(body.name).trim();
    } else {
      members[idx].name = String(body.name).trim();
    }
  }

  // Address is shared; phone routes to the correct field based on who is logged in
  if (body.address !== undefined) members[idx].address = String(body.address).trim();
  if (body.phone !== undefined) {
    if (isSpouse) {
      const sp = String(body.phone).trim();
      if (sp) members[idx].spouse_phone = sp; else delete members[idx].spouse_phone;
    } else {
      members[idx].phone = String(body.phone).trim();
    }
  }
  // show_in_directory controls each person's own entry
  if (body.show_in_directory !== undefined) {
    if (isSpouse) {
      members[idx].spouse_show_in_directory = body.show_in_directory === true;
    } else {
      members[idx].show_in_directory = body.show_in_directory === true;
    }
  }
  // email_updates: each person controls their own subscription
  if (body.email_updates !== undefined) {
    if (isSpouse) {
      members[idx].spouse_email_updates = body.email_updates === true;
    } else {
      members[idx].email_updates = body.email_updates === true;
    }
  }

  // Only the primary account holder can set spouse info; stripe_email is never writable here
  if (!isSpouse) {
    if (body.spouse_name !== undefined) {
      const sn = String(body.spouse_name).trim();
      if (sn) members[idx].spouse_name = sn; else delete members[idx].spouse_name;
    }
    if (body.spouse_email !== undefined) {
      const se = String(body.spouse_email).toLowerCase().trim();
      if (se) members[idx].spouse_email = se; else delete members[idx].spouse_email;
    }
    if (body.spouse_phone !== undefined) {
      const sp = String(body.spouse_phone).trim();
      if (sp) members[idx].spouse_phone = sp; else delete members[idx].spouse_phone;
    }
    if (body.spouse_show_in_directory !== undefined) {
      members[idx].spouse_show_in_directory = body.spouse_show_in_directory === true;
    }
    // removeSpouse flag wipes all spouse fields at once
    if (body.remove_spouse === true) {
      delete members[idx].spouse_name;
      delete members[idx].spouse_email;
      delete members[idx].spouse_show_in_directory;
    }
  }

  await env.HOA_DATA.put('members', JSON.stringify(members));
  const displayName = isSpouse ? members[idx].spouse_name : members[idx].name;
  return json({ ok: true, name: displayName });
}

// GET /api/members
async function handleMembers(request, env, email) {
  const members = await getMembers(env);
  const admin = isAdmin(email, members);
  const rows = [];

  for (const m of members) {
    // Primary member row
    if (admin || m.show_in_directory === true) {
      rows.push({
        name: m.name, email: m.email,
        address: m.address || '', phone: m.phone || '',
        ...(admin && !m.show_in_directory ? { hidden_from_directory: true } : {}),
      });
    }
    // Spouse row — only if spouse has a name
    if (m.spouse_name) {
      if (admin || m.spouse_show_in_directory === true) {
        rows.push({
          name: m.spouse_name, email: m.spouse_email || '',
          address: m.address || '', phone: m.spouse_phone || m.phone || '',
          ...(admin && !m.spouse_show_in_directory ? { hidden_from_directory: true } : {}),
        });
      }
    }
  }

  // Sort by address
  rows.sort((a, b) => (a.address || '').localeCompare(b.address || ''));
  return json(rows);
}

// GET /api/newsletters
async function handleNewsletters(request, env) {
  const data = await env.HOA_DATA.get('newsletters') || '[]';
  return new Response(data, { headers: { 'Content-Type': 'application/json' } });
}

// GET /api/budget
async function handleBudget(request, env) {
  const data = await env.HOA_DATA.get('budget') || '[]';
  return new Response(data, { headers: { 'Content-Type': 'application/json' } });
}

// GET /api/posts — public, no auth required
async function handlePosts(request, env) {
  const data = await env.HOA_DATA.get('posts') || '[]';
  return new Response(data, { headers: { 'Content-Type': 'application/json' } });
}

// GET/POST/DELETE /api/admin/posts — admin only
async function handleAdminPosts(request, env, email) {
  const members = await getMembers(env);
  if (!isAdmin(email, members)) return json({ error: 'Unauthorized' }, 403);

  if (request.method === 'GET') {
    const data = await env.HOA_DATA.get('posts') || '[]';
    return new Response(data, { headers: { 'Content-Type': 'application/json' } });
  }

  if (request.method === 'POST') {
    const body = await request.json();
    const title = (body.title || '').trim();
    const content = (body.content || '').trim();
    if (!title || !content) return json({ error: 'Title and content required' }, 400);

    const posts = JSON.parse(await env.HOA_DATA.get('posts') || '[]');
    const post = {
      id: crypto.randomUUID(),
      title,
      content,
      created_at: new Date().toISOString(),
    };
    posts.unshift(post); // newest first
    await env.HOA_DATA.put('posts', JSON.stringify(posts));

    // Collect subscribed recipients (undefined = subscribed by default)
    const recipients = [];
    for (const m of members) {
      if (m.email_updates !== false) {
        recipients.push({ email: m.email, name: m.name });
      }
      if (m.spouse_email && m.spouse_email_updates !== false) {
        recipients.push({ email: m.spouse_email, name: m.spouse_name || m.name });
      }
    }

    // Send notification emails
    const dateStr = new Date(post.created_at).toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric',
    });
    const safeContent = content.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\n/g,'<br>');
    await Promise.allSettled(recipients.map(r =>
      fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: HOA_FROM_EMAIL,
          to: r.email,
          subject: `Trillium Lane HOA: ${post.title}`,
          html: `
            <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#2c2c2c">
              <div style="background:#2d5a3d;padding:1.5rem;text-align:center">
                <h1 style="color:#fff;font-size:1.2rem;margin:0">Trillium Lane HOA</h1>
              </div>
              <div style="padding:2rem;background:#fff;border:1px solid #d4e6da">
                <p style="font-size:0.85rem;color:#888;margin-bottom:0.5rem">${dateStr}</p>
                <h2 style="color:#1e3f2b;font-size:1.3rem;margin-bottom:1.25rem;font-family:Georgia,serif">${post.title}</h2>
                <div style="line-height:1.75;color:#333">${safeContent}</div>
                <div style="margin-top:2rem;padding-top:1rem;border-top:1px solid #eee">
                  <a href="https://trilliumlane.org/members/" style="color:#2d5a3d;font-size:0.9rem;">View in Members Portal →</a>
                </div>
              </div>
              <p style="text-align:center;color:#aaa;font-size:0.75rem;padding:1rem 1rem 0">
                Trillium Lane HOA &middot; Mill Valley, CA<br>
                <a href="https://trilliumlane.org/members/" style="color:#aaa;">Manage email preferences in your member portal</a>
              </p>
            </div>
          `,
        }),
      })
    ));

    return json({ ok: true, post, sent: recipients.length });
  }

  if (request.method === 'DELETE') {
    const { id } = await request.json();
    if (!id) return json({ error: 'id required' }, 400);
    const posts = JSON.parse(await env.HOA_DATA.get('posts') || '[]');
    await env.HOA_DATA.put('posts', JSON.stringify(posts.filter(p => p.id !== id)));
    return json({ ok: true });
  }

  return json({ error: 'Method not allowed' }, 405);
}

// GET/PUT /api/admin/members
async function handleAdminMembers(request, env, email) {
  const members = await getMembers(env);
  if (!isAdmin(email, members)) return json({ error: 'Unauthorized' }, 403);
  if (request.method === 'GET') return json(members);
  if (request.method === 'PUT') {
    await env.HOA_DATA.put('members', JSON.stringify(await request.json()));
    return json({ ok: true });
  }
  return json({ error: 'Method not allowed' }, 405);
}

// GET/PUT /api/admin/newsletters
async function handleAdminNewsletters(request, env, email) {
  const members = await getMembers(env);
  if (!isAdmin(email, members)) return json({ error: 'Unauthorized' }, 403);
  if (request.method === 'GET') {
    const data = await env.HOA_DATA.get('newsletters') || '[]';
    return new Response(data, { headers: { 'Content-Type': 'application/json' } });
  }
  if (request.method === 'PUT') {
    await env.HOA_DATA.put('newsletters', JSON.stringify(await request.json()));
    return json({ ok: true });
  }
  return json({ error: 'Method not allowed' }, 405);
}

// GET/PUT /api/admin/budget
async function handleAdminBudget(request, env, email) {
  const members = await getMembers(env);
  if (!isAdmin(email, members)) return json({ error: 'Unauthorized' }, 403);
  if (request.method === 'GET') {
    const data = await env.HOA_DATA.get('budget') || '[]';
    return new Response(data, { headers: { 'Content-Type': 'application/json' } });
  }
  if (request.method === 'PUT') {
    await env.HOA_DATA.put('budget', JSON.stringify(await request.json()));
    return json({ ok: true });
  }
  return json({ error: 'Method not allowed' }, 405);
}

// GET /api/stripe/portal — redirect authenticated user to Stripe Billing Portal
async function handleStripePortal(request, env, email) {
  if (!env.STRIPE_SECRET_KEY) return json({ error: 'Server misconfiguration' }, 500);

  // Resolve the stripe_email for this household (works for both primary and spouse logins)
  const members = await getMembers(env);
  const found = findHousehold(members, email);
  const household = found ? members[found.idx] : null;
  const stripeEmail = household?.stripe_email || household?.email || email;

  // Find the Stripe customer by stripe_email
  const searchRes = await fetch(
    `https://api.stripe.com/v1/customers/search?query=email:'${encodeURIComponent(stripeEmail)}'`,
    { headers: { 'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}` } }
  );
  if (!searchRes.ok) return json({ error: 'Could not look up subscription' }, 500);
  const searchData = await searchRes.json();

  if (!searchData.data || searchData.data.length === 0) {
    return new Response('No Stripe subscription found for this account. If you pay by check, contact bruce@trilliumlane.org to cancel.', {
      status: 404, headers: { 'Content-Type': 'text/plain' },
    });
  }

  // Create a billing portal session
  const portalRes = await fetch('https://api.stripe.com/v1/billing_portal/sessions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      customer: searchData.data[0].id,
      return_url: 'https://trilliumlane.org/members/',
    }),
  });

  if (!portalRes.ok) {
    const err = await portalRes.text();
    console.error('Stripe portal error:', err);
    return json({ error: 'Could not create portal session' }, 500);
  }

  const { url } = await portalRes.json();
  return Response.redirect(url, 302);
}

// POST /api/stripe-webhook
async function handleStripeWebhook(request, env) {
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
  const rawBody = await request.text();
  const sigHeader = request.headers.get('Stripe-Signature') || '';
  if (!env.STRIPE_WEBHOOK_SECRET) return json({ error: 'Server misconfiguration' }, 500);

  const parts = Object.fromEntries(sigHeader.split(',').map(p => p.split('=')));
  const timestamp = parts.t;
  const receivedSig = parts.v1;
  if (!timestamp || !receivedSig) return json({ error: 'Invalid signature header' }, 400);
  if (Math.floor(Date.now() / 1000) - parseInt(timestamp) > 300) return json({ error: 'Timestamp too old' }, 400);

  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.STRIPE_WEBHOOK_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
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
      const paymentMethod = session.amount_total === 24000 ? 'autopay_annual' : 'autopay_monthly';
      // Match by primary email, spouse email, or previously stored stripe_email
      let idx = members.findIndex(m => m.email.toLowerCase() === email);
      if (idx === -1) idx = members.findIndex(m => m.spouse_email && m.spouse_email.toLowerCase() === email);
      if (idx === -1) idx = members.findIndex(m => m.stripe_email && m.stripe_email.toLowerCase() === email);
      if (idx !== -1) {
        members[idx].payment_status = 'current';
        members[idx].payment_method = paymentMethod;
        members[idx].stripe_email = email; // lock in the Stripe email for portal use
      } else {
        members.push({ name: session.customer_details?.name || '', email, stripe_email: email, address: '', phone: '', payment_status: 'current', payment_method: paymentMethod, is_admin: false });
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
      let idx = members.findIndex(m => m.email.toLowerCase() === email);
      if (idx === -1) idx = members.findIndex(m => m.spouse_email && m.spouse_email.toLowerCase() === email);
      if (idx === -1) idx = members.findIndex(m => m.stripe_email && m.stripe_email.toLowerCase() === email);
      if (idx !== -1) {
        members[idx].payment_status = 'current';
        members[idx].stripe_email = email;
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
      let idx = members.findIndex(m => m.email.toLowerCase() === email);
      if (idx === -1) idx = members.findIndex(m => m.spouse_email && m.spouse_email.toLowerCase() === email);
      if (idx === -1) idx = members.findIndex(m => m.stripe_email && m.stripe_email.toLowerCase() === email);
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
// Main fetch handler
// ---------------------------------------------------------------------------
export default {
  async fetch(request, env, ctx) {
    const url  = new URL(request.url);
    const path = url.pathname;

    // ── Public auth endpoints (no session required) ──
    if (path.startsWith('/api/auth/')) {
      if (path === '/api/auth/request-otp') return handleRequestOTP(request, env);
      if (path === '/api/auth/verify-otp')  return handleVerifyOTP(request, env);
      if (path === '/api/auth/logout')      return handleLogout(request, env);
      return json({ error: 'Not found' }, 404);
    }

    // ── Stripe webhook (has its own auth via signature) ──
    if (path === '/api/stripe-webhook') return handleStripeWebhook(request, env);

    // ── Public posts feed (no auth required) ──
    if (path === '/api/posts' && request.method === 'GET') return handlePosts(request, env);

    // ── Protected API endpoints ──
    if (path.startsWith('/api/')) {
      const email = await getEmailFromSession(request, env);
      if (!email) return json({ error: 'Not authenticated' }, 401);

      if (path === '/api/me')                return handleMe(request, env, email);
      if (path === '/api/profile')           return handleProfile(request, env, email);
      if (path === '/api/members')           return handleMembers(request, env, email);
      if (path === '/api/newsletters')       return handleNewsletters(request, env);
      if (path === '/api/budget')            return handleBudget(request, env);
      if (path === '/api/stripe/portal')     return handleStripePortal(request, env, email);
      if (path === '/api/admin/members')     return handleAdminMembers(request, env, email);
      if (path === '/api/admin/newsletters') return handleAdminNewsletters(request, env, email);
      if (path === '/api/admin/budget')      return handleAdminBudget(request, env, email);
      if (path === '/api/admin/posts')       return handleAdminPosts(request, env, email);
      return json({ error: 'Not found' }, 404);
    }

    // ── Protected pages: redirect to login if no valid session ──
    if (path.startsWith('/members/') && !path.startsWith('/members/login')) {
      const email = await getEmailFromSession(request, env);
      if (!email) return loginRedirect(path);
    }
    if (path.startsWith('/admin/')) {
      const email = await getEmailFromSession(request, env);
      if (!email) return loginRedirect(path);
    }

    // ── All other requests → static assets ──
    return env.ASSETS.fetch(request);
  },
};
