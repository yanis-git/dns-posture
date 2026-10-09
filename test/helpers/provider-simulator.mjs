// No sockets: imported only by the test child processes, never shipped in npm.
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { ENDPOINTS } from '../../lib/ovh-client.mjs';
ENDPOINTS['ovh-nowhere'] = 'https://ovh.invalid';
const file = process.env.SIM_STATE;
const initial = {
  records: [{ id: 1, fieldType: 'MX', subDomain: '', target: '10 mx1.ovh.net.', ttl: 3600 }],
  writes: [],
};
const state = file && existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : initial;
const save = () => { if (file) writeFileSync(file, JSON.stringify(state)); };
const response = (body, status = 200) => new Response(JSON.stringify(body), { status });
const cf = (result, info) => response({ success: true, result, ...(info ? { result_info: info } : {}) });
const native = (r) => ({ id: String(r.id), name: r.subDomain ? `${r.subDomain}.example.com` : 'example.com', type: r.fieldType, ttl: r.ttl,
  content: r.fieldType === 'MX' ? r.target.split(' ')[1] : r.target, ...(r.fieldType === 'MX' ? { priority: 10 } : {}),
  proxied: false, comment: 'example metadata', tags: ['scope:example'], settings: {},
});
const fromNative = (r, id) => ({ id, subDomain: r.name === 'example.com' ? '' : r.name.slice(0, -12), fieldType: r.type,
  ttl: r.ttl, target: r.type === 'MX' ? `${r.priority} ${r.content}` : r.content,
});
globalThis.fetch = async (url, init = {}) => {
  const parsed = new URL(url);
  if (!['ovh.invalid', 'api.cloudflare.com'].includes(parsed.hostname)) throw new Error('Unexpected network destination');
  const method = init.method || 'GET';
  const path = parsed.pathname;
  const cloudflare = parsed.hostname === 'api.cloudflare.com';
  if (path.endsWith('/auth/time')) return response(Math.round(Date.now() / 1000));
  if (path.endsWith('/me')) return response({ nichandle: 'example-account' });
  if (path === '/client/v4/zones') return cf([{ id: 'zone1', name: 'example.com', account: { id: 'account1' } }], { page: 1, count: 1, total_count: 1, total_pages: 1 });
  if (path === '/domain/zone') return response(['example.com']);
  if (path.endsWith('/export')) return response('$ORIGIN example.com.\n');
  const recordsPath = cloudflare ? '/client/v4/zones/zone1/dns_records' : '/domain/zone/example.com/record';
  if (method === 'GET') {
    if (path === recordsPath) {
      const rows = process.env.SIM_FAIL === 'diverge' && state.writes.length ? [] : state.records;
      return cloudflare ? cf(rows.map(native), { page: 1, count: rows.length, total_count: rows.length, total_pages: 1 }) : response(rows.map((r) => r.id));
    }
    const record = state.records.find((r) => String(r.id) === path.split('/').at(-1));
    if (record) return response(record);
    throw new Error(`Unexpected read: ${path}`);
  }
  state.writes.push([method, path]);
  save();
  if (process.env.SIM_FAIL === 'write' && state.writes.length === 2) throw new Error('Simulated uncertain write');
  if (path.endsWith('/refresh')) return response(null);
  const id = path === recordsPath ? Date.now() + state.writes.length : Number(path.split('/').at(-1));
  if (method === 'DELETE') state.records = state.records.filter((r) => r.id !== id);
  else {
    const body = JSON.parse(init.body);
    const old = state.records.find((r) => r.id === id);
    const record = cloudflare ? fromNative(body, id) : { ...old, ...body, id };
    if (method === 'POST') state.records.push(record);
    else state.records = state.records.map((r) => r.id === id ? record : r);
  }
  save();
  return cloudflare ? cf({ id: String(id) }) : response({ id });
};
