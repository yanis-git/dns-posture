// OVH zone-file parsing + dormant/active classification.

const RR_TYPES = new Set([
  'A', 'AAAA', 'CAA', 'CNAME', 'DKIM', 'DMARC', 'DNAME', 'LOC', 'MX', 'NAPTR',
  'NS', 'PTR', 'SOA', 'SPF', 'SRV', 'SSHFP', 'TLSA', 'TXT',
]);

// Strip the trailing comment. A ';' inside quotes belongs to the data
// (v=DKIM1; p=, v=DMARC1; p=reject; ...) and must not truncate the rdata.
function stripComment(raw) {
  let inQuotes = false;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (c === '"' && raw[i - 1] !== '\\') inQuotes = !inQuotes;
    else if (c === ';' && !inQuotes) return raw.slice(0, i);
  }
  return raw;
}

/**
 * Locate the RR type token.
 *
 * A record whose *name* is spelled like a type ("mx", "ns", "a", "srv"...) is a
 * perfectly legal subdomain, so the first matching token is not necessarily the
 * type: in `mx 3600 IN A 1.2.3.4` the type is A, not MX. A nameless record is
 * always indented, so on an unindented line token 0 is the name and the search
 * starts at 1. The fallback keeps malformed lines parsing as before.
 */
function findTypeIndex(tokens, hasOwnName) {
  const from = hasOwnName ? 1 : 0;
  for (let i = from; i < tokens.length; i++) {
    if (RR_TYPES.has(tokens[i].toUpperCase())) return i;
  }
  return from === 0 ? -1 : tokens.findIndex((t) => RR_TYPES.has(t.toUpperCase()));
}

/**
 * Parse an OVH zone export. Returns [{ name, type, rdata }].
 * The SOA (multi-line, parenthesised) is skipped.
 */
export function parseZone(text) {
  const records = [];
  let lastName = '@';
  let inSoa = false;

  for (const raw of text.split('\n')) {
    const line = stripComment(raw).trimEnd();
    if (!line.trim()) continue;

    if (inSoa) {
      if (line.includes(')')) inSoa = false;
      continue;
    }
    if (line.startsWith('$')) continue; // $TTL, $ORIGIN

    const tokens = line.trim().split(/\s+/);
    const hasOwnName = !/^\s/.test(raw) && tokens.length > 1;
    const typeIdx = findTypeIndex(tokens, hasOwnName);
    if (typeIdx === -1) continue;

    const type = tokens[typeIdx].toUpperCase();
    // Before the type: [name] [ttl] [class]. A name is only present when the
    // line does not start with a blank and the 1st token is neither TTL nor IN.
    const head = tokens.slice(0, typeIdx).filter((t) => t.toUpperCase() !== 'IN' && !/^\d+$/.test(t));
    const name = /^\s/.test(raw) ? lastName : (head[0] ?? lastName);
    lastName = name;

    if (type === 'SOA') {
      if (!line.includes(')')) inSoa = true;
      continue;
    }
    records.push({ name, type, rdata: tokens.slice(typeIdx + 1).join(' ') });
  }
  return records;
}

// Mail servers that indicate a genuinely used mailbox.
const REAL_MAIL = [
  { re: /aspmx.*google|google.*aspmx|googlemail/i, label: 'Google Workspace' },
  { re: /mail\.protection\.outlook\.com|outlook\.com/i, label: 'Microsoft 365' },
  { re: /\.mailgun\.|sendgrid|mandrill|sparkpost|amazonses|mailjet/i, label: 'transactional ESP' },
  { re: /ex\d*\.mail\.ovh|pro\d*\.mail\.ovh|\.mxplan\./i, label: 'OVH Exchange/Pro' },
  { re: /zoho|protonmail|fastmail|gandi|infomaniak/i, label: 'other mail host' },
];

// OVH default MX, two naming schemes: mx1.mail.ovh.net and mx1/mxa.ovh.net.
// Careful: MX Plan (real OVH mailboxes) uses the same hosts — DNS alone cannot
// prove that no mailbox exists.
const OVH_DEFAULT_MX = /^mx[a-z0-9]+\.(mail\.)?ovh\.net\.?$/i;

// RFC 7505 "null MX": `MX 0 .` declares that the domain accepts no mail at all.
// It is one of the records this tool publishes, so it must never be mistaken for
// an unrecognised mail host — otherwise a hardened domain reads as mail-active
// and is skipped for ever on the next run.
const NULL_MX = /^\.$/;

// Internal marker of the OVH web redirection service.
const OVH_REDIRECT_TXT = /^"?\d+\|/;

// IP range of the OVH shared-hosting / parking cluster.
const OVH_PARKING_IP = /^213\.186\.33\.\d+$/;

/**
 * Classify a zone. Returns { state, signals, counts }.
 *   dormant      -> no sign of mail or web usage
 *   mail-active  -> MX pointing at a real provider, DO NOT touch without checking
 *   web-active   -> web content served, mail probably unused
 *
 * `domain` is optional: it only serves to recognise a CNAME pointing at the root
 * of its own zone (www -> example.com.), so it is not counted twice.
 */
export function classify(records, { domain = null } = {}) {
  const signals = [];
  const mx = records.filter((r) => r.type === 'MX');
  const txt = records.filter((r) => ['TXT', 'SPF', 'DKIM', 'DMARC'].includes(r.type));
  const cname = records.filter((r) => r.type === 'CNAME');
  const a = records.filter((r) => ['A', 'AAAA'].includes(r.type));

  // WHERE the mail lives matters as much as whether it exists. A delegated
  // sending subdomain (mg.example.com -> an ESP) makes the ZONE active without
  // making the APEX send, and the two answer different questions:
  //   state      -> may the zone be hardened at all?   (fail-safe: assume in use)
  //   apexSends  -> is `v=spf1 -all` at the apex safe?  (the narrower question)
  // The state stays conservative either way; apexSends only ever informs.
  const atApex = (name) => ['@', ''].includes(String(name || '').toLowerCase());
  let mailActive = false;
  let apexSends = false;
  for (const rec of mx) {
    const host = rec.rdata.split(/\s+/).pop() || '';
    const hit = REAL_MAIL.find((p) => p.re.test(host));
    const where = atApex(rec.name) ? '' : ` on ${rec.name}`;
    if (NULL_MX.test(host)) signals.push(`null MX (RFC 7505): receives no mail${where}`);
    else if (hit) {
      mailActive = true;
      if (atApex(rec.name)) apexSends = true;
      signals.push(`MX ${hit.label}${where} (${host})`);
    } else if (OVH_DEFAULT_MX.test(host)) signals.push(`default OVH MX${where} (${host})`);
    else if (host) {
      mailActive = true;
      if (atApex(rec.name)) apexSends = true;
      signals.push(`unknown MX, check it${where} (${host})`);
    }
  }

  // A published DKIM key means the domain signs mail. The ovhmoXXXX-selectorN
  // ._domainkey CNAMEs are OVH MX Plan's DKIM delegation: mail, not web.
  const dkimTxt = txt.filter((r) => /_domainkey/i.test(r.name) && !/p=\s*"?\s*$|p=""/.test(r.rdata));
  const dkimCname = cname.filter((r) => /_domainkey/i.test(r.name));
  // `sel._domainkey` signs for the apex; `sel._domainkey.mg` signs for the
  // sending subdomain and says nothing about the apex.
  const apexDkim = (r) => /(^|\.)_domainkey$/i.test(r.name);
  if (dkimTxt.length) {
    mailActive = true;
    if (dkimTxt.some(apexDkim)) apexSends = true;
    signals.push(`${dkimTxt.length} published DKIM key(s)`);
  }
  if (dkimCname.length) {
    mailActive = true;
    if (dkimCname.some(apexDkim)) apexSends = true;
    signals.push(`delegated DKIM (${dkimCname.length} selector(s), typical of OVH MX Plan)`);
  }

  const verif = txt.filter((r) => /site-verification|^"?MS=|facebook-domain|apple-domain|stripe|atlassian/i.test(r.rdata));
  if (verif.length) signals.push(`${verif.length} verification TXT (third-party service attached)`);

  const redirect = txt.filter((r) => OVH_REDIRECT_TXT.test(r.rdata));
  if (redirect.length) signals.push('!! OVH web redirection active (TXT must not be removed on its own)');

  if (a.some((r) => OVH_PARKING_IP.test(r.rdata))) signals.push('OVH parking');

  const ftp = cname.filter((r) => /^ftp$/i.test(r.name));
  if (ftp.length) signals.push('ftp CNAME');

  // Web: any A/AAAA/CNAME pointing somewhere other than the OVH parking. The
  // root and www count as much as a subdomain — a site at the apex is still a
  // site, and filing it as dormant would make the inventory lie.
  // A CNAME to the root of its own zone (www -> example.com.) is not distinct
  // content: it is an alias, it follows the fate of the apex.
  const fqdn = (s) => String(s).trim().replace(/\.$/, '').toLowerCase();
  const isApexAlias = (r) => r.type === 'CNAME' && domain && fqdn(r.rdata) === fqdn(domain);

  const hosts = [...a, ...cname].filter((r) => !['ftp', '*'].includes(r.name.toLowerCase())
    && !r.name.startsWith('_') && !/_domainkey/i.test(r.name));
  const live = hosts.filter((r) => !OVH_PARKING_IP.test(r.rdata) && !isApexAlias(r));
  const apexLive = live.filter((r) => ['@', 'www'].includes(r.name.toLowerCase()));
  const subLive = live.filter((r) => !['@', 'www'].includes(r.name.toLowerCase()));
  const webActive = live.length > 0;

  if (apexLive.length) signals.push(`root active -> ${[...new Set(apexLive.map((r) => r.rdata))].join(', ')}`);
  if (subLive.length) signals.push(`${subLive.length} subdomain(s): ${subLive.slice(0, 4).map((r) => r.name).join(', ')}${subLive.length > 4 ? '...' : ''}`);

  const state = mailActive ? 'mail-active' : webActive ? 'web-active' : 'dormant';
  if (state === 'dormant' && !signals.length) signals.push('empty zone');
  if (mailActive && !apexSends) signals.push('mail is delegated to subdomains — the apex itself does not send');

  return {
    state,
    signals,
    apexSends,
    counts: { mx: mx.length, txt: txt.length, cname: cname.length, a: a.length, total: records.length },
  };
}
