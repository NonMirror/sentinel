// Benign loopback fixture. Dependencies live in the explicit temporary npm root.
const { createRequire } = require('node:module');
const { resolve } = require('node:path');
const { createHash } = require('node:crypto');
const fixtureRequire = createRequire(resolve(process.argv[2], 'package.json'));
const express = fixtureRequire('express');
const multer = fixtureRequire('multer');
const app = express();
const hash = data => createHash('sha256').update(data).digest('hex');
const lists = values => Object.fromEntries(Object.entries(values || {}).map(([k, v]) => [k, Array.isArray(v) ? v : [v]]));

app.use((req, res, next) => {
  req.fixtureChunks = [];
  req.on('data', chunk => req.fixtureChunks.push(chunk));
  next();
});
app.use(express.json({ type: ['application/json', 'application/*+json'], limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.post('/upload', multer({ storage: multer.memoryStorage(), limits: { fileSize: 1048576, files: 2, fields: 10 } }).any());
app.use((req, res) => {
  const path = decodeURIComponent(req.path);
  const media = (req.headers['content-type'] || '').split(';')[0];
  const isJson = media === 'application/json' || media.endsWith('+json');
  const files = {};
  for (const file of req.files || []) {
    (files[file.fieldname] ||= []).push({ filename: file.originalname, size: file.size, sha256: hash(file.buffer) });
  }
  const policies = {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',
  };
  if (['/policy/valid', '/policy/repeated', '/policy/invalid', '/policy/referrer-invalid', '/policy/referrer-unknown'].includes(path)) {
    for (const [name, value] of Object.entries(policies)) res.set(name, path === '/policy/invalid' ? 'invalid-policy' : value);
  }
  if (path === '/policy/referrer-invalid') res.set('Referrer-Policy', 'no-referrer, origin no-referrer');
  if (path === '/policy/referrer-unknown') res.set('Referrer-Policy', 'no-referrer, future-policy');
  if (path === '/policy/repeated') {
    res.append('Cross-Origin-Opener-Policy', 'unsafe-none');
    res.append('Referrer-Policy', 'unsafe-url');
  }
  if (path === '/cookies') {
    res.cookie('first', 'ordinary', { httpOnly: true, sameSite: 'lax' });
    res.cookie('second', 'another', { httpOnly: true, sameSite: 'lax' });
  }
  res.json({ method: req.method, path, body_sha256: hash(Buffer.concat(req.fixtureChunks)),
             query: lists(req.query), form: isJson ? {} : lists(req.body), files,
             json: isJson ? req.body : null });
});
const server = app.listen(0, '127.0.0.1', () => {
  console.log(JSON.stringify({ framework: 'express', port: server.address().port,
    packages: { node: process.version, express: fixtureRequire('express/package.json').version,
                multer: fixtureRequire('multer/package.json').version } }));
});
process.on('SIGTERM', () => server.close(() => process.exit(0)));
