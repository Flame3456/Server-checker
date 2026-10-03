'use strict';

const API_BASE_URL = 'https://checkapi.piglax.ru';
const MAX_JSON_BYTES = 2 * 1024 * 1024;

async function fetchJson(endpoint) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(new URL(endpoint, API_BASE_URL), {
      signal: controller.signal,
      headers: { accept: 'application/json' },
    });
    if (!response.ok) throw new Error(`API HTTP ${response.status}`);
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > MAX_JSON_BYTES) throw new Error('API response is too large');
    return JSON.parse(text);
  } finally {
    clearTimeout(timer);
  }
}

function normalizeSignatures(data) {
  const raw = Array.isArray(data)
    ? data
    : data?.signatures || data?.strings || data?.checkerSignatures || [];
  if (!Array.isArray(raw)) return [];
  return raw.map((item) => {
    if (typeof item === 'string') return { name: item, category: 'client', distinctive: true };
    return {
      name: String(item?.name || '').trim().toLowerCase(),
      category: ['ghost', 'loader', 'client', 'configExt'].includes(item?.category) ? item.category : 'client',
      distinctive: item?.distinctive !== false,
    };
  }).filter((item) => /^[a-z0-9а-я_.:-]{2,80}$/i.test(item.name)).slice(0, 1000);
}

async function syncSignatures() {
  let manifest;
  try {
    manifest = await fetchJson('/v1/manifest');
  } catch {
    manifest = await fetchJson('/v1/strings');
  }

  const signatures = normalizeSignatures(manifest);
  if (!signatures.length) throw new Error('API returned no signatures');
  const version = String(manifest.version || manifest.stringsVersion || manifest.signatureVersion || 'remote');
  return { ok: true, version, signatures };
}

module.exports = { API_BASE_URL, fetchJson, syncSignatures };
