require('dotenv').config();
const model = process.argv[2] || process.env.GEMINI_MODEL || 'gemini-3.8-flash';
const level = process.argv[3]; // tùy chọn: low / minimal

const body = {
    contents: [{ role: 'user', parts: [{ text: 'Cho 3 gợi ý ngắn để uống đủ nước mỗi ngày.' }] }],
    generationConfig: { maxOutputTokens: 512 }
};
if (level) body.generationConfig.thinkingConfig = { thinkingLevel: level };

(async () => {
    const t = Date.now();
    try {
        const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-goog-api-key': process.env.GEMINI_API_KEY.trim() },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(90000)
        });
        const text = await r.text();
        console.log(`${model}${level ? ' [' + level + ']' : ''} -> HTTP ${r.status} sau ${((Date.now() - t) / 1000).toFixed(1)}s`);
        console.log(text.slice(0, 400));
    } catch (e) {
        console.log(`Lỗi sau ${((Date.now() - t) / 1000).toFixed(1)}s:`, e.name, e.message);
    }
})();