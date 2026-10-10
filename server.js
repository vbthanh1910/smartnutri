require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { createClient } = require('@supabase/supabase-js');

const scrypt = promisify(crypto.scrypt);

const app = express();
const PORT = process.env.PORT || 3002;

// Báo rõ biến nào đang thiếu (không in giá trị để tránh lộ key)
const REQUIRED = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'ADMIN_PASSWORD'];
const missing = REQUIRED.filter(k => !process.env[k] || !process.env[k].trim());
if (missing.length) {
    console.error('Thiếu biến trong file .env: ' + missing.join(', '));
    console.error('Các biến đang đọc được: ' + (REQUIRED.filter(k => !missing.includes(k)).join(', ') || '(không có)'));
    console.error('Kiểm tra: đúng tên biến, dạng KEY=value (không dấu cách quanh "="), file lưu mã hóa UTF-8, nằm cùng thư mục với server.js.');
    process.exit(1);
}
const { SUPABASE_URL, SUPABASE_SECRET_KEY, ADMIN_PASSWORD } = process.env;

const supabase = createClient(SUPABASE_URL.trim(), SUPABASE_SECRET_KEY.trim());

app.set('trust proxy', 1); // cần khi chạy sau proxy của Render
app.use(express.json({ limit: '100kb' }));
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Tiện ích ----------
function safeEqual(a, b) {
    const ha = crypto.createHash('sha256').update(String(a)).digest();
    const hb = crypto.createHash('sha256').update(String(b)).digest();
    return crypto.timingSafeEqual(ha, hb);
}

// Bọc handler async để lỗi bất ngờ (mất mạng...) không làm sập server (Express 4)
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(err => {
    console.error('[SERVER] Lỗi không mong đợi:', err);
    res.status(500).json({ status: 'error', message: 'Lỗi máy chủ.' });
});

// Chỉ admin có mật khẩu mới đọc/xóa/cập nhật đơn
function requireAdmin(req, res, next) {
    const pw = req.get('x-admin-password') || '';
    if (!safeEqual(pw, ADMIN_PASSWORD.trim())) {
        return res.status(401).json({ status: 'error', message: 'Sai mật khẩu quản trị.' });
    }
    next();
}

// Giới hạn số lần gọi / phút / IP
const limiterMaps = [];
function makeLimiter(max, message) {
    const hits = new Map();
    limiterMaps.push(hits);
    return function (req, res, next) {
        const now = Date.now();
        const rec = hits.get(req.ip);
        if (!rec || now > rec.reset) {
            hits.set(req.ip, { count: 1, reset: now + 60000 });
            return next();
        }
        rec.count++;
        if (rec.count > max) {
            return res.status(429).json({ status: 'error', message });
        }
        next();
    };
}
setInterval(() => {
    const now = Date.now();
    for (const m of limiterMaps) for (const [ip, rec] of m) if (now > rec.reset) m.delete(ip);
}, 60000).unref();

const orderLimiter = makeLimiter(20, 'Gửi quá nhanh, vui lòng thử lại sau 1 phút.');
const authLimiter = makeLimiter(10, 'Thử quá nhiều lần, vui lòng đợi 1 phút.');

function num(v, min, max) {
    const n = Number(v);
    return Number.isFinite(n) && n >= min && n <= max ? n : null;
}

// ---------- Tài khoản khách hàng ----------
async function hashPassword(pw) {
    const salt = crypto.randomBytes(16);
    const hash = await scrypt(pw, salt, 64);
    return salt.toString('hex') + ':' + hash.toString('hex');
}

async function verifyPassword(pw, stored) {
    const [saltHex, hashHex] = String(stored || '').split(':');
    if (!saltHex || !hashHex) return false;
    const expected = Buffer.from(hashHex, 'hex');
    const hash = await scrypt(pw, Buffer.from(saltHex, 'hex'), expected.length);
    return hash.length === expected.length && crypto.timingSafeEqual(hash, expected);
}

const sha = t => crypto.createHash('sha256').update(t).digest('hex');

function normalizePhone(v) {
    return String(v || '').replace(/[\s.\-]/g, '');
}

async function createSession(customerId) {
    const token = crypto.randomBytes(32).toString('hex');
    const { error } = await supabase.from('customer_sessions').insert({
        token_hash: sha(token),
        customer_id: customerId,
        expires_at: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString()
    });
    if (error) throw error;
    return token;
}

function bearerToken(req) {
    const m = /^Bearer ([a-f0-9]{64})$/.exec(req.get('authorization') || '');
    return m ? m[1] : null;
}

// Trả về khách hàng nếu token hợp lệ, ngược lại null
async function getCustomer(req) {
    const token = bearerToken(req);
    if (!token) return null;
    const { data, error } = await supabase
        .from('customer_sessions')
        .select('expires_at, customers(id, full_name, phone, profile)')
        .eq('token_hash', sha(token))
        .maybeSingle();
    if (error || !data || !data.customers) return null;
    if (new Date(data.expires_at) < new Date()) return null;
    return data.customers;
}

const requireCustomer = wrap(async (req, res, next) => {
    const customer = await getCustomer(req);
    if (!customer) {
        return res.status(401).json({ status: 'error', message: 'Vui lòng đăng nhập.' });
    }
    req.customer = customer;
    next();
});

app.post('/api/auth/register', authLimiter, wrap(async (req, res) => {
    const b = req.body || {};
    const name = String(b.name || '').trim().slice(0, 100);
    const phone = normalizePhone(b.phone);
    const password = String(b.password || '');

    if (!name) return res.status(400).json({ status: 'error', message: 'Vui lòng nhập họ tên.' });
    if (!/^\+?[0-9]{8,15}$/.test(phone)) {
        return res.status(400).json({ status: 'error', message: 'Số điện thoại không hợp lệ (8-15 chữ số).' });
    }
    if (password.length < 6 || password.length > 72) {
        return res.status(400).json({ status: 'error', message: 'Mật khẩu phải từ 6 đến 72 ký tự.' });
    }

    const { data, error } = await supabase
        .from('customers')
        .insert({ full_name: name, phone, password_hash: await hashPassword(password) })
        .select('id, full_name, phone, profile')
        .single();

    if (error) {
        if (error.code === '23505') {
            return res.status(409).json({ status: 'error', message: 'Số điện thoại này đã được đăng ký. Hãy đăng nhập.' });
        }
        console.error('[SUPABASE] Lỗi khi tạo tài khoản:', error.message);
        return res.status(500).json({ status: 'error', message: 'Không tạo được tài khoản.' });
    }

    const token = await createSession(data.id);
    console.log(`[AUTH] Tài khoản mới #${data.id}`);
    res.status(201).json({ status: 'success', token, customer: data });
}));

app.post('/api/auth/login', authLimiter, wrap(async (req, res) => {
    const b = req.body || {};
    const phone = normalizePhone(b.phone);
    const password = String(b.password || '');

    const { data, error } = await supabase
        .from('customers')
        .select('id, full_name, phone, profile, password_hash')
        .eq('phone', phone)
        .maybeSingle();

    if (error) {
        console.error('[SUPABASE] Lỗi khi đăng nhập:', error.message);
        return res.status(500).json({ status: 'error', message: 'Không đăng nhập được.' });
    }

    const ok = data && await verifyPassword(password, data.password_hash);
    if (!ok) {
        return res.status(401).json({ status: 'error', message: 'Sai số điện thoại hoặc mật khẩu.' });
    }

    const token = await createSession(data.id);
    const { password_hash, ...customer } = data;
    res.json({ status: 'success', token, customer });
}));

app.post('/api/auth/logout', wrap(async (req, res) => {
    const token = bearerToken(req);
    if (token) await supabase.from('customer_sessions').delete().eq('token_hash', sha(token));
    res.json({ status: 'success' });
}));

app.get('/api/me', requireCustomer, (req, res) => {
    res.json({ status: 'success', customer: req.customer });
});

// Khách xem các đơn của chính mình + tiến độ
app.get('/api/my-orders', requireCustomer, wrap(async (req, res) => {
    const { data, error } = await supabase
        .from('orders')
        .select('id, created_at, status, preparing_at, completed_at, total_calories, target_calories_kcal, items')
        .eq('customer_id', req.customer.id)
        .order('created_at', { ascending: false })
        .limit(100);

    if (error) {
        console.error('[SUPABASE] Lỗi khi đọc đơn của khách:', error.message);
        return res.status(500).json({ status: 'error', message: 'Không đọc được danh sách đơn.' });
    }
    res.json(data);
}));

// ---------- Khách chốt đơn (đăng nhập hoặc không đều được) ----------
app.post('/api/orders', orderLimiter, wrap(async (req, res) => {
    const b = req.body || {};
    const profile = b.profile || {};
    const customer = await getCustomer(req); // null nếu là khách vãng lai

    const name = String(b.customerName || '').trim().slice(0, 100);
    const phone = String(b.customerPhone || '').trim();
    if (!name) {
        return res.status(400).json({ status: 'error', message: 'Thiếu họ tên.' });
    }
    if (!/^[0-9+\s.-]{8,20}$/.test(phone)) {
        return res.status(400).json({ status: 'error', message: 'Số điện thoại không hợp lệ.' });
    }

    // Kiểm tra từng món, tự tính lại tổng calo ở server (không tin số client gửi)
    if (!Array.isArray(b.items) || b.items.length < 1 || b.items.length > 50) {
        return res.status(400).json({ status: 'error', message: 'Đơn phải có từ 1 đến 50 món.' });
    }
    const items = [];
    for (const i of b.items) {
        const cals = num(i && i.cals, 0, 5000);
        const qty = num(i && i.qty, 1, 99);
        const itemName = String((i && i.name) || '').trim().slice(0, 120);
        if (cals === null || qty === null || !Number.isInteger(qty) || !itemName) {
            return res.status(400).json({ status: 'error', message: 'Có món ăn không hợp lệ.' });
        }
        items.push({ id: String((i && i.id) || ''), name: itemName, cals, qty });
    }
    const totalCalories = items.reduce((s, i) => s + i.cals * i.qty, 0);

    const row = {
        customer_id: customer ? customer.id : null,
        customer_name: name,
        customer_phone: phone,
        gender: ['male', 'female'].includes(profile.gender) ? profile.gender : null,
        age: num(profile.age, 1, 120),
        height_cm: num(profile.height, 50, 260),
        weight_kg: num(profile.weight, 10, 400),
        bmi: num(profile.bmi, 5, 100),
        bmi_status: String(profile.bmiStatus || '').slice(0, 50),
        bmr_kcal: num(profile.bmr, 0, 10000),
        tdee_kcal: num(profile.tdee, 0, 20000),
        target_calories_kcal: num(profile.targetCalories, 0, 20000),
        protein_g: num(profile.proteinGrams, 0, 2000),
        carbs_g: num(profile.carbGrams, 0, 2000),
        fat_g: num(profile.fatGrams, 0, 2000),
        total_calories: totalCalories,
        items
    };

    const { data, error } = await supabase
        .from('orders')
        .insert(row)
        .select('id')
        .single();

    if (error) {
        console.error('[SUPABASE] Lỗi khi lưu đơn:', error.message);
        return res.status(500).json({ status: 'error', message: 'Không lưu được đơn hàng.' });
    }

    // Nhớ chỉ số cơ thể cho lần đặt sau (chỉ khi đã đăng nhập)
    if (customer) {
        const { error: pErr } = await supabase
            .from('customers')
            .update({ profile: { gender: row.gender, age: row.age, height: row.height_cm, weight: row.weight_kg } })
            .eq('id', customer.id);
        if (pErr) console.error('[SUPABASE] Lỗi khi lưu hồ sơ khách:', pErr.message);
    }

    console.log(`[SUPABASE] Đã lưu đơn #${data.id} của ${name}${customer ? ` (tài khoản #${customer.id})` : ' (khách vãng lai)'}`);
    res.status(201).json({ status: 'success', id: data.id, linked: !!customer, message: `Đã lưu đơn #${data.id}!` });
}));

// ---------- Admin ----------
app.get('/api/orders', requireAdmin, wrap(async (req, res) => {
    const { data, error } = await supabase
        .from('orders')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(200);

    if (error) {
        console.error('[SUPABASE] Lỗi khi đọc đơn:', error.message);
        return res.status(500).json({ status: 'error', message: 'Không đọc được danh sách đơn.' });
    }
    res.json(data);
}));

// Đổi trạng thái đơn. Body: { "status": "pending" | "preparing" | "completed" }
// (vẫn nhận { "completed": true|false } để tương thích bản cũ)
app.patch('/api/orders/:id', requireAdmin, wrap(async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ status: 'error', message: 'Mã đơn không hợp lệ.' });
    }

    const body = req.body || {};
    let status = body.status;
    if (status === undefined && typeof body.completed === 'boolean') {
        status = body.completed ? 'completed' : 'pending';
    }
    if (!['pending', 'preparing', 'completed'].includes(status)) {
        return res.status(400).json({ status: 'error', message: 'Trạng thái không hợp lệ.' });
    }

    const now = new Date().toISOString();
    const patch = { status, completed_at: status === 'completed' ? now : null };
    if (status === 'preparing') patch.preparing_at = now;
    else if (status === 'pending') patch.preparing_at = null;

    const { data, error } = await supabase
        .from('orders')
        .update(patch)
        .eq('id', id)
        .select('id, status, preparing_at, completed_at');

    if (error) {
        console.error('[SUPABASE] Lỗi khi cập nhật đơn:', error.message);
        return res.status(500).json({ status: 'error', message: 'Không cập nhật được đơn.' });
    }
    if (!data || data.length === 0) {
        return res.status(404).json({ status: 'error', message: 'Không tìm thấy đơn.' });
    }
    console.log(`[SUPABASE] Đơn #${id} -> ${data[0].status}`);
    res.json({ status: 'success', order: data[0] });
}));

app.delete('/api/orders', requireAdmin, wrap(async (req, res) => {
    const { error } = await supabase.from('orders').delete().gt('id', 0);
    if (error) {
        console.error('[SUPABASE] Lỗi khi xóa đơn:', error.message);
        return res.status(500).json({ status: 'error', message: 'Không xóa được đơn.' });
    }
    res.json({ status: 'success' });
}));

app.listen(PORT, () => {
    console.log(`Server đang chạy. Khách: http://localhost:${PORT}  |  Đơn của tôi: http://localhost:${PORT}/orders.html  |  Admin: http://localhost:${PORT}/admin.html`);
});
