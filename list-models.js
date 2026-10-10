require('dotenv').config();
const key = process.env.GEMINI_API_KEY.trim();
const H = { 'Content-Type': 'application/json', 'x-goog-api-key': key };

async function timed(label, fn) {
    const t = Date.now();
    try { const out = await fn(); console.log(`${label}: ${out} (${((Date.now() - t) / 1000).toFixed(1)}s)`); }
    catch (e) { console.log(`${label}: ${e.name} (${((Date.now() - t) / 1000).toFixed(1)}s)`); }
}

(async () => {
    // 1) Kết nối + danh sách model dùng được với key này
    let models = [];
    await timed('Liệt kê model', async () => {
        const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models?pageSize=100', { headers: H, signal: AbortSignal.timeout(15000) });
        const j = await r.json();
        models = (j.models || [])
            .filter(m => (m.supportedGenerationMethods || []).includes('generateContent'))
            .map(m => m.name.replace('models/', ''));
        return `HTTP ${r.status}, ${models.length} model`;
    });
    console.log(models.join('\n'));

    // 2) Thử nhanh từng model "flash" (tối đa 30s mỗi model)
    for (const m of models.filter(n => /flash/.test(n)).slice(0, 6)) {
        await timed(`Thử ${m}`, async () => {
            const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent`, {
                method: 'POST', headers: H, signal: AbortSignal.timeout(30000),
                body: JSON.stringify({ contents: [{ parts: [{ text: 'Chào bạn, trả lời đúng 1 câu ngắn.' }] }], generationConfig: { maxOutputTokens: 200 } })
            });
            return 'HTTP ' + r.status;
        });
    }
})();