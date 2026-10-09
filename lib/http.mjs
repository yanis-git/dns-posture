// Only reads are retried. A failed write may already have reached the provider.
export async function request(url, options = {}, { timeout = 15000, retries = 2, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  const read = !options.method || options.method === 'GET';
  for (let attempt = 0; ; attempt++) {
    let response;
    try {
      response = await fetch(url, { ...options, signal: AbortSignal.timeout(timeout) });
      // Consume inside the deadline; returning a Response would leave body reads unbounded.
      const body = await response.text();
      if (read && [429, 500, 502, 503, 504].includes(response.status) && attempt < retries) {
        const retry = response.headers?.get('retry-after');
        const delay = retry ? (/^\d+$/.test(retry) ? Number(retry) * 1000 : Date.parse(retry) - Date.now()) : 250 * 2 ** attempt;
        // Do not retry earlier than requested, or wait indefinitely in a CLI.
        if (!Number.isFinite(delay) || delay > 30000) return { response, body };
        await sleep(Math.max(0, delay));
        continue;
      }
      return { response, body };
    } catch (error) {
      if (!read || attempt >= retries) throw error;
      await sleep(250 * 2 ** attempt);
    }
  }
}
