// Stripe webhook handler
// Automatically updates member payment status in KV when Stripe events occur.
//
// Environment variables required (set in Cloudflare Pages → Settings → Environment Variables):
//   STRIPE_WEBHOOK_SECRET  — from Stripe Dashboard → Developers → Webhooks → signing secret

const PRICE_MONTHLY = 'price_1TaN7r2NsbOSaiK9BQjhidGr';  // $20/month
const PRICE_YEARLY  = 'price_1TaN7r2NsbOSaiK9A2lsODMZ';  // $240/year

// ---------------------------------------------------------------------------
// Stripe signature verification using Web Crypto API (no Node.js needed)
// ---------------------------------------------------------------------------
async function verifySignature(rawBody, signatureHeader, secret) {
  const parts = Object.fromEntries(
    signatureHeader.split(',').map(p => p.split('='))
  );
  const timestamp = parts.t;
  const receivedSig = parts.v1;
  if (!timestamp || !receivedSig) return false;

  // Reject events older than 5 minutes (replay attack protection)
  const age = Math.floor(Date.now() / 1000) - parseInt(timestamp);
  if (age > 300) return false;

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signatureBytes = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${timestamp}.${rawBody}`)
  );

  const computedSig = Array.from(new Uint8Array(signatureBytes))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return computedSig === receivedSig;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// Determine payment method from Stripe line items (price ID matching)
function paymentMethodFromPriceId(priceId) {
  if (priceId === PRICE_MONTHLY) return 'autopay_monthly';
  if (priceId === PRICE_YEARLY)  return 'autopay_annual';
  return 'autopay_monthly'; // safe default
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------
export async function onRequest({ request, env }) {
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

  const rawBody = await request.text();
  const sigHeader = request.headers.get('Stripe-Signature') || '';

  if (!env.STRIPE_WEBHOOK_SECRET) {
    console.error('STRIPE_WEBHOOK_SECRET not set');
    return json({ error: 'Server misconfiguration' }, 500);
  }

  const valid = await verifySignature(rawBody, sigHeader, env.STRIPE_WEBHOOK_SECRET);
  if (!valid) {
    console.error('Invalid Stripe signature');
    return json({ error: 'Invalid signature' }, 400);
  }

  const event = JSON.parse(rawBody);
  const members = JSON.parse(await env.HOA_DATA.get('members') || '[]');

  console.log(`Stripe event received: ${event.type}`);

  switch (event.type) {

    // -----------------------------------------------------------------------
    // New subscription created via Payment Link
    // Automatically adds the member if they don't exist yet, or updates them.
    // -----------------------------------------------------------------------
    case 'checkout.session.completed': {
      const session = event.data.object;
      if (session.mode !== 'subscription') break; // ignore one-time payments

      const email = session.customer_details?.email?.toLowerCase();
      const name  = session.customer_details?.name || '';
      if (!email) break;

      // Determine plan from amount_total (in cents): 2000 = $20, 24000 = $240
      const amount = session.amount_total;
      const paymentMethod = amount === 24000 ? 'autopay_annual' : 'autopay_monthly';

      const idx = members.findIndex(m => m.email.toLowerCase() === email);
      if (idx !== -1) {
        // Existing member — update payment info
        members[idx].payment_status = 'current';
        members[idx].payment_method = paymentMethod;
        if (!members[idx].name && name) members[idx].name = name;
      } else {
        // New member — add them automatically
        members.push({
          name,
          email,
          address: '',
          phone: '',
          payment_status: 'current',
          payment_method: paymentMethod,
          is_admin: false,
        });
      }

      await env.HOA_DATA.put('members', JSON.stringify(members));
      console.log(`checkout.session.completed: upserted member ${email} as ${paymentMethod}`);
      break;
    }

    // -----------------------------------------------------------------------
    // Recurring payment succeeded (annual or monthly renewal)
    // -----------------------------------------------------------------------
    case 'invoice.payment_succeeded': {
      const invoice = event.data.object;
      // Only handle subscription invoices, not one-off charges
      if (!invoice.subscription) break;

      const email = invoice.customer_email?.toLowerCase();
      if (!email) break;

      // Also update payment method in case they switched plans
      const priceId = invoice.lines?.data?.[0]?.price?.id;
      const idx = members.findIndex(m => m.email.toLowerCase() === email);
      if (idx !== -1) {
        members[idx].payment_status = 'current';
        if (priceId) members[idx].payment_method = paymentMethodFromPriceId(priceId);
        await env.HOA_DATA.put('members', JSON.stringify(members));
        console.log(`invoice.payment_succeeded: ${email} set to current`);
      }
      break;
    }

    // -----------------------------------------------------------------------
    // Payment failed — Stripe will retry but mark member as past due now
    // -----------------------------------------------------------------------
    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      if (!invoice.subscription) break;

      const email = invoice.customer_email?.toLowerCase();
      if (!email) break;

      const idx = members.findIndex(m => m.email.toLowerCase() === email);
      if (idx !== -1) {
        members[idx].payment_status = 'past_due';
        await env.HOA_DATA.put('members', JSON.stringify(members));
        console.log(`invoice.payment_failed: ${email} set to past_due`);
      }
      break;
    }

    // -----------------------------------------------------------------------
    // Subscription cancelled (member cancelled or Stripe gave up after retries)
    // -----------------------------------------------------------------------
    case 'customer.subscription.deleted': {
      // subscription.deleted doesn't include email directly — we catch this
      // case via invoice.payment_failed events fired before cancellation.
      // Log it for visibility.
      console.log(`customer.subscription.deleted: id=${event.data.object.id}`);
      break;
    }

    default:
      console.log(`Unhandled event type: ${event.type}`);
  }

  // Always return 200 so Stripe doesn't retry
  return json({ received: true });
}
