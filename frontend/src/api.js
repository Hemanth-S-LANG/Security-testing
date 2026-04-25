const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

async function req(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);
  let res;
  try {
    res = await fetch(BASE + path, opts);
  } catch (err) {
    throw new Error('Network error: backend unreachable or CORS blocked');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Request failed' }));
    throw new Error(err.detail || 'Request failed');
  }
  return res.json();
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const api = {
  generate: (swagger_spec, base_url) =>
    req('POST', '/generate', { swagger_spec, base_url }),
  run: (swagger_spec, base_url) =>
    req('POST', '/run', { swagger_spec, base_url }),
  getResults: async (run_id) => {
    const maxAttempts = 3;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await req('GET', `/runs/${run_id}/results`);
      } catch (err) {
        if (attempt === maxAttempts) throw err;
        await sleep(800 * attempt);
      }
    }
  },
};