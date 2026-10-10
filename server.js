require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3002;

const { SUPABASE_URL, SUPABASE_SECRET_KEY, ADMIN_PASSWORD } = process.env;
if (!SUPABASE_URL || !SUPABASE_SECRET_KEY || !ADMIN_PASSWORD) {
    console.error('Thiếu SUPABASE_URL, SUPABASE_SECRET_KEY hoặc ADMIN_PASSWORD trong file .env');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL.trim(), SUPABASE_SECRET_KEY.trim());

app.set('trust proxy', 1); // cần khi chạy sau proxy của Render
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Tiện ích ----------
function safeEqual(a, b) {
    const ha = crypto.createHash('sha256').update(String(a)).digest();
    const hb = crypto.createHash('sha256').update(String(b)).digest();
    return crypto.timingSafeEqual(ha, hb);
}

// Chỉ admin có mật khẩu mới đọc/xóa được đơn
function requireAdmin(req, res, next) {
    const pw = req.get('x-admin-password') || '';
    if (!safeEqual(pw, ADMIN_PASSWORD.trim())) {
        return res.status(401).json({ status: 'error', message: 'Sai mật khẩu quản trị.' });
    }
    next();
}

// Giới hạn 20 đơn / phút / IP để tránh bị gửi rác
const hits = new Map();
function rateLimit(req, res, next) {
    const now = Date.now();
    const rec = hits.get(req.ip);
    if (!rec || now > rec.reset) {
        hits.set(req.ip, { count: 1, reset: now + 60000 });
        return next();
    }
    rec.count++;
    if (rec.count > 20) {
        return res.status(429).json({ status: 'error', message: 'Gửi quá nhanh, vui lòng thử lại sau 1 phút.' });
    }
    next();
}

function num(v, min, max) {
    const n = Number(v);
    return Number.isFinite(n) && n >= min && n <= max ? n : null;
}

// ---------- Khách chốt đơn ----------
app.post('/api/orders', rateLimit, async (req, res) => {
    const b = req.body || {};
    const profile = b.profile || {};

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

    console.log(`[SUPABASE] Đã lưu đơn #${data.id} của ${name}`);
    res.status(201).json({ status: 'success', id: data.id, message: `Đã lưu đơn #${data.id}!` });
});

// ---------- Admin ----------
app.get('/api/orders', requireAdmin, async (req, res) => {
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
});

app.delete('/api/orders', requireAdmin, async (req, res) => {
    const { error } = await supabase.from('orders').delete().gt('id', 0);
    if (error) {
        console.error('[SUPABASE] Lỗi khi xóa đơn:', error.message);
        return res.status(500).json({ status: 'error', message: 'Không xóa được đơn.' });
    }
    res.json({ status: 'success' });
});

app.listen(PORT, () => {
    console.log(`Server đang chạy. Khách: http://localhost:${PORT}  |  Admin: http://localhost:${PORT}/admin.html`);
});
