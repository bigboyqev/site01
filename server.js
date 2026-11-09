const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'subscribers.json');

fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]');

const load = () => JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
const save = (list) => {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(list, null, 2));
  fs.renameSync(tmp, DATA_FILE);
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const app = express();
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ['https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
    },
  },
}));
app.use(express.json({ limit: '2kb' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] })); // /privacy -> privacy.html, /terms -> terms.html

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' } });

app.post('/api/subscribe', limiter, (req, res) => {
  const { email, website } = req.body || {};
  if (website) return res.json({ ok: true }); // honeypot: silently accept bots
  const clean = String(email || '').trim().toLowerCase();
  if (!EMAIL_RE.test(clean) || clean.length > 254) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  const list = load();
  if (!list.some((s) => s.email === clean)) {
    list.push({ email: clean, createdAt: new Date().toISOString() });
    save(list);
  }
  res.json({ ok: true }); // same response for new and existing emails
});

app.get('/api/subscribers', (req, res) => {
  if (!ADMIN_KEY || req.query.key !== ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });
  const list = load();
  if (req.query.format === 'csv') {
    res.type('text/csv').send('email,createdAt\n' + list.map((s) => `${s.email},${s.createdAt}`).join('\n'));
  } else res.json({ count: list.length, subscribers: list });
});


/* ===================== M-PESA STK PUSH (Daraja) ===================== */
const MPESA = {
  env: process.env.MPESA_ENV || 'sandbox',
  key: process.env.MPESA_CONSUMER_KEY || '',
  secret: process.env.MPESA_CONSUMER_SECRET || '',
  shortcode: process.env.MPESA_SHORTCODE || '174379',
  till: process.env.MPESA_PARTYB || '',            // Buy Goods only: your Till number
  passkey: process.env.MPESA_PASSKEY || '',
  type: process.env.MPESA_TXN_TYPE || 'CustomerPayBillOnline', // or CustomerBuyGoodsOnline
  callbackBase: (process.env.MPESA_CALLBACK_BASE || '').replace(/\/$/, ''), // public HTTPS origin
  callbackSecret: process.env.MPESA_CALLBACK_SECRET || '',
  price: Number(process.env.TICKET_PRICE_KES || 100),
};
const MPESA_BASE = process.env.MPESA_BASE_URL ||
  (MPESA.env === 'production' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke');
const ORDERS_FILE = process.env.ORDERS_FILE || path.join(__dirname, 'data', 'orders.json');
fs.mkdirSync(path.dirname(ORDERS_FILE), { recursive: true });
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, '[]');
const loadOrders = () => JSON.parse(fs.readFileSync(ORDERS_FILE, 'utf8'));
const saveOrders = (o) => { const t = ORDERS_FILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(o, null, 2)); fs.renameSync(t, ORDERS_FILE); };

let tokenCache = { value: '', exp: 0 };
async function getToken() {
  if (tokenCache.value && Date.now() < tokenCache.exp) return tokenCache.value;
  const auth = Buffer.from(`${MPESA.key}:${MPESA.secret}`).toString('base64');
  const r = await fetch(`${MPESA_BASE}/oauth/v1/generate?grant_type=client_credentials`,
    { headers: { Authorization: `Basic ${auth}` }, signal: AbortSignal.timeout(15000) });
  if (!r.ok) throw new Error(`token ${r.status}`);
  const d = await r.json();
  tokenCache = { value: d.access_token, exp: Date.now() + (Number(d.expires_in || 3599) - 60) * 1000 };
  return tokenCache.value;
}
const eatTimestamp = () => new Date(Date.now() + 3 * 3600 * 1000).toISOString().replace(/[-:T]/g, '').slice(0, 14);
function normalizePhone(raw) {
  const p = String(raw || '').replace(/[\s+\-()]/g, '');
  if (/^0[17]\d{8}$/.test(p)) return '254' + p.slice(1);
  if (/^254[17]\d{8}$/.test(p)) return p;
  return null;
}

const stkLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many payment attempts. Please wait a few minutes.' } });

app.get('/api/pay/config', (req, res) => res.json({ price: MPESA.price, currency: 'KES', maxQty: 10 }));

app.post('/api/pay/stk', stkLimiter, async (req, res) => {
  try {
    const phone = normalizePhone(req.body && req.body.phone);
    const qty = Math.floor(Number(req.body && req.body.qty));
    if (!phone) return res.status(400).json({ error: 'Enter a valid Safaricom number, e.g. 0712 345 678.' });
    if (!(qty >= 1 && qty <= 10)) return res.status(400).json({ error: 'Choose between 1 and 10 tickets.' });
    if (!MPESA.key || !MPESA.secret || !MPESA.passkey || !MPESA.callbackBase || !MPESA.callbackSecret)
      return res.status(503).json({ error: 'Payments are not configured yet.' });

    const amount = MPESA.price * qty;                 // amount is ALWAYS computed on the server
    const id = crypto.randomUUID();
    const ts = eatTimestamp();
    const password = Buffer.from(MPESA.shortcode + MPESA.passkey + ts).toString('base64');
    const token = await getToken();
    const r = await fetch(`${MPESA_BASE}/mpesa/stkpush/v1/processrequest`, {
      method: 'POST', signal: AbortSignal.timeout(20000),
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        BusinessShortCode: MPESA.shortcode, Password: password, Timestamp: ts,
        TransactionType: MPESA.type, Amount: amount, PartyA: phone,
        PartyB: MPESA.type === 'CustomerBuyGoodsOnline' && MPESA.till ? MPESA.till : MPESA.shortcode,
        PhoneNumber: phone,
        CallBackURL: `${MPESA.callbackBase}/api/pay/callback/${MPESA.callbackSecret}`,
        AccountReference: 'TalantaTickets', TransactionDesc: `${qty} ticket(s)`,
      }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok || d.ResponseCode !== '0') {
      console.error('STK push rejected', r.status, d);
      return res.status(502).json({ error: 'Could not start the M-Pesa prompt. Please try again.' });
    }
    const orders = loadOrders();
    orders.push({ id, checkoutRequestId: d.CheckoutRequestID, phone, qty, amount, status: 'pending', createdAt: new Date().toISOString() });
    saveOrders(orders);
    res.json({ ok: true, orderId: id });
  } catch (e) {
    console.error('STK error', e.message);
    res.status(502).json({ error: 'Payment service unavailable. Please try again.' });
  }
});

// Apply a result (from the callback or a status query) to an order. Idempotent: only pending orders change.
function applyResult(checkoutRequestId, cb) {
  const orders = loadOrders();
  const o = orders.find((x) => x.checkoutRequestId === checkoutRequestId);
  if (!o || o.status !== 'pending') return;
  const code = Number(cb.ResultCode);
  if (code === 0) {
    const items = (cb.CallbackMetadata && cb.CallbackMetadata.Item) || [];
    const get = (n) => (items.find((i) => i.Name === n) || {}).Value;
    const amt = get('Amount');
    if (amt !== undefined && Number(amt) !== o.amount) { o.status = 'review'; o.note = 'amount mismatch'; }
    else {
      o.status = 'paid'; o.paidAt = new Date().toISOString();
      o.receipt = String(get('MpesaReceiptNumber') || '');
      if (amt === undefined) o.note = 'confirmed via status query';
    }
  } else {
    o.status = code === 1032 ? 'cancelled' : 'failed';
    o.note = String(cb.ResultDesc || '');
  }
  o.updatedAt = new Date().toISOString();
  saveOrders(orders);
}

// Safaricom calls this. It is not signed, so the URL carries a secret and we verify the amount.
app.post('/api/pay/callback/:secret', (req, res) => {
  const ok = MPESA.callbackSecret && req.params.secret.length === MPESA.callbackSecret.length &&
    crypto.timingSafeEqual(Buffer.from(req.params.secret), Buffer.from(MPESA.callbackSecret));
  if (!ok) return res.status(403).end();
  const cb = req.body && req.body.Body && req.body.Body.stkCallback;
  if (cb && cb.CheckoutRequestID) applyResult(cb.CheckoutRequestID, cb);
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
});

// Safety net if the callback never arrives: ask Safaricom directly.
async function queryOrder(o) {
  try {
    const ts = eatTimestamp();
    const password = Buffer.from(MPESA.shortcode + MPESA.passkey + ts).toString('base64');
    const token = await getToken();
    const r = await fetch(`${MPESA_BASE}/mpesa/stkpushquery/v1/query`, {
      method: 'POST', signal: AbortSignal.timeout(15000),
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ BusinessShortCode: MPESA.shortcode, Password: password, Timestamp: ts, CheckoutRequestID: o.checkoutRequestId }),
    });
    const d = await r.json().catch(() => ({}));
    if (d.ResultCode !== undefined) applyResult(o.checkoutRequestId, { ResultCode: d.ResultCode, ResultDesc: d.ResultDesc });
  } catch (e) { /* still processing or temporary error: try again on the next poll */ }
}
const lastQuery = new Map();
const statusLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });

app.get('/api/pay/status/:id', statusLimiter, async (req, res) => {
  let o = loadOrders().find((x) => x.id === req.params.id);
  if (!o) return res.status(404).json({ error: 'Not found' });
  if (o.status === 'pending' && Date.now() - Date.parse(o.createdAt) > 25000 && Date.now() - (lastQuery.get(o.id) || 0) > 10000) {
    lastQuery.set(o.id, Date.now());
    await queryOrder(o);
    o = loadOrders().find((x) => x.id === req.params.id) || o;
  }
  res.json({ status: o.status, receipt: o.status === 'paid' && o.receipt ? o.receipt : undefined, amount: o.amount });
});

app.get('/api/orders', (req, res) => {
  if (!ADMIN_KEY || req.query.key !== ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });
  const list = loadOrders();
  if (req.query.format === 'csv') {
    res.type('text/csv').send('id,status,amount,qty,phone,receipt,createdAt\n' +
      list.map((o) => [o.id, o.status, o.amount, o.qty, o.phone, o.receipt || '', o.createdAt].join(',')).join('\n'));
  } else res.json({ count: list.length, paid: list.filter((o) => o.status === 'paid').length, orders: list });
});
/* =================== END M-PESA STK PUSH =================== */

app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
