#!/usr/bin/env node
/* ACE dashboard CI checks — runs on every push via GitHub Actions.
   Deterministic guards against the real failure modes of a paste-deploy
   workflow: truncated pastes, broken JS, duplicate IDs, leaked secrets. */
const fs = require('fs'), cp = require('child_process'), os = require('os'), path = require('path');
const src = fs.readFileSync('index.html', 'utf8');
let fails = 0;
const fail = m => { console.error('  ✗ ' + m); fails++; };
const pass = m => console.log('  ✓ ' + m);

// 1. truncation guard — a partial paste is the most likely deploy accident
if (/<\/html>\s*$/.test(src)) pass('file ends with </html> (no truncated paste)');
else fail('file does not end with </html> — looks like a truncated paste');

// 2. merge-conflict markers
if (/^(<{7}|={7}|>{7}) /m.test(src)) fail('git conflict markers found');
else pass('no conflict markers');

// 3. version badge present
const ver = src.match(/VERSION:\s*'([\d.]+)'/);
if (ver) pass('CONFIG.VERSION present: v' + ver[1]);
else fail('CONFIG.VERSION missing');

// 4. every inline <script> block parses
const blocks = [...src.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
let jsOk = true;
blocks.forEach((b, i) => {
  const f = path.join(os.tmpdir(), 'blk' + i + '.js');
  fs.writeFileSync(f, b);
  const r = cp.spawnSync('node', ['--check', f], { encoding: 'utf8' });
  if (r.status !== 0){ jsOk = false; fail('script block ' + i + ' has a syntax error:\n' + r.stderr.trim()); }
});
if (jsOk) pass(blocks.length + ' inline script block(s) parse cleanly');

// 5. duplicate element IDs (HTML only — script bodies stripped first)
const htmlOnly = src.replace(/<script(?![^>]*src=)[^>]*>[\s\S]*?<\/script>/g, '');
const seen = {}, dupes = new Set();
for (const m of htmlOnly.matchAll(/\bid="([^"]+)"/g)){
  if (seen[m[1]]) dupes.add(m[1]); seen[m[1]] = 1;
}
if (dupes.size) fail('duplicate element IDs: ' + [...dupes].join(', '));
else pass('all element IDs unique');

// 6. secret scan — keys that must live only in Apps Script Script Properties
if (/sb_secret_/.test(src)) fail('Supabase sb_secret_ key found in file');
else pass('no sb_secret_ keys');
let sk = false;
for (const m of src.matchAll(/eyJ[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)\./g)){
  try {
    const p = JSON.parse(Buffer.from(m[1].replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString());
    if (p.role === 'service_role'){ sk = true; fail('Supabase SERVICE ROLE key found in file — remove immediately'); }
  } catch(e){}
}
if (!sk) pass('no service_role JWTs (anon key only)');
if (/\bAC[0-9a-f]{32}\b/.test(src)) fail('Twilio Account SID found in file');
else pass('no Twilio credentials');

console.log(fails ? '\n' + fails + ' check(s) FAILED' : '\nAll checks passed');
process.exit(fails ? 1 : 0);
