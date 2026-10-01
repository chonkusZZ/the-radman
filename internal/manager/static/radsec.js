// RadSEC certificate generator.
// The key pair is created with WebCrypto inside this page. Only a certificate signing request (public key)
// is sent to the server. Key material lives in Uint8Arrays that are zeroed on "Wipe", on page hide and after 5 minutes.
// Nothing is written to localStorage, sessionStorage, IndexedDB or cookies.
(function () {
  'use strict';
  var app = document.getElementById('radsec-app');
  if (!app) return;
  var $ = function (id) { return document.getElementById(id); };
  var te = new TextEncoder();
  var secret = null; // { key, cert, ca: Uint8Array }
  var timerId = null, deadline = 0;
  var TTL_MS = 5 * 60 * 1000;

  // ---------- minimal DER encoder ----------
  function concat() {
    var n = 0, i, a = arguments;
    for (i = 0; i < a.length; i++) n += a[i].length;
    var out = new Uint8Array(n), o = 0;
    for (i = 0; i < a.length; i++) { out.set(a[i], o); o += a[i].length; }
    return out;
  }
  function derLen(n) {
    if (n < 128) return Uint8Array.of(n);
    var b = [];
    while (n > 0) { b.unshift(n & 255); n = Math.floor(n / 256); }
    return Uint8Array.from([0x80 | b.length].concat(b));
  }
  function tlv(tag, content) { return concat(Uint8Array.of(tag), derLen(content.length), content); }
  function seq() { return tlv(0x30, concat.apply(null, arguments)); }
  function set() { return tlv(0x31, concat.apply(null, arguments)); }
  function intFromBytes(bytes) {
    var i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    var b = bytes.slice(i);
    if (b[0] & 0x80) b = concat(Uint8Array.of(0), b);
    return tlv(0x02, b);
  }
  function oid(str) {
    var p = str.split('.').map(Number), out = [p[0] * 40 + p[1]];
    for (var i = 2; i < p.length; i++) {
      var v = p[i], tmp = [v & 0x7f];
      v = Math.floor(v / 128);
      while (v > 0) { tmp.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
      out = out.concat(tmp);
    }
    return tlv(0x06, Uint8Array.from(out));
  }
  function utf8String(s) { return tlv(0x0c, te.encode(s)); }
  function bitString(b) { return tlv(0x03, concat(Uint8Array.of(0), b)); }

  // base64 + PEM straight from bytes to ASCII bytes (no intermediate JS strings for key material)
  var B64 = te.encode('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/');
  function pemBytes(label, der) {
    var lines = [], head = te.encode('-----BEGIN ' + label + '-----\n'), tail = te.encode('-----END ' + label + '-----\n');
    var enc = new Uint8Array(Math.ceil(der.length / 3) * 4), o = 0, i;
    for (i = 0; i < der.length; i += 3) {
      var b0 = der[i], b1 = i + 1 < der.length ? der[i + 1] : 0, b2 = i + 2 < der.length ? der[i + 2] : 0;
      enc[o++] = B64[b0 >> 2];
      enc[o++] = B64[((b0 & 3) << 4) | (b1 >> 4)];
      enc[o++] = i + 1 < der.length ? B64[((b1 & 15) << 2) | (b2 >> 6)] : 61;
      enc[o++] = i + 2 < der.length ? B64[b2 & 63] : 61;
    }
    var parts = [head];
    for (i = 0; i < enc.length; i += 64) { parts.push(enc.subarray(i, Math.min(i + 64, enc.length))); parts.push(Uint8Array.of(10)); }
    parts.push(tail);
    var out = concat.apply(null, parts);
    enc.fill(0);
    return out;
  }

  // WebCrypto returns ECDSA signatures as r||s; X.509 wants DER SEQUENCE { INTEGER r, INTEGER s }
  function ecSigToDer(sig) {
    var h = sig.length / 2;
    return seq(intFromBytes(sig.slice(0, h)), intFromBytes(sig.slice(h)));
  }

  var ALGOS = {
    ec256: { gen: { name: 'ECDSA', namedCurve: 'P-256' }, sign: { name: 'ECDSA', hash: 'SHA-256' }, sigOid: '1.2.840.10045.4.3.2', ec: true },
    ec384: { gen: { name: 'ECDSA', namedCurve: 'P-384' }, sign: { name: 'ECDSA', hash: 'SHA-384' }, sigOid: '1.2.840.10045.4.3.3', ec: true },
    rsa2048: { gen: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' }, sign: { name: 'RSASSA-PKCS1-v1_5' }, sigOid: '1.2.840.113549.1.1.11', ec: false },
    rsa3072: { gen: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 3072, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' }, sign: { name: 'RSASSA-PKCS1-v1_5' }, sigOid: '1.2.840.113549.1.1.11', ec: false }
  };

  async function generate(algoName, cn) {
    var a = ALGOS[algoName];
    var kp = await crypto.subtle.generateKey(a.gen, true, ['sign', 'verify']);
    var pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
    var spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
    var subject = seq(set(seq(oid('2.5.4.3'), utf8String(cn))));
    var info = seq(tlv(0x02, Uint8Array.of(0)), subject, spki, tlv(0xa0, new Uint8Array(0)));
    var sig = new Uint8Array(await crypto.subtle.sign(a.sign, kp.privateKey, info));
    if (a.ec) sig = ecSigToDer(sig);
    var sigAlg = a.ec ? seq(oid(a.sigOid)) : seq(oid(a.sigOid), Uint8Array.of(5, 0));
    var csr = seq(info, sigAlg, bitString(sig));
    var csrPem = new TextDecoder().decode(pemBytes('CERTIFICATE REQUEST', csr));
    var keyPem = pemBytes('PRIVATE KEY', pkcs8);
    pkcs8.fill(0);
    kp = null; // drop CryptoKey references
    return { csrPem: csrPem, keyPem: keyPem };
  }

  // ---------- UI ----------
  function show(id, on) { $(id).classList.toggle('hidden', !on); }
  function err(msg) { var e = $('rs-error'); e.textContent = msg; show('rs-error', true); }

  function wipe() {
    if (secret) {
      for (var k in secret) if (secret[k] && secret[k].fill) secret[k].fill(0);
      secret = null;
    }
    if (timerId) { clearInterval(timerId); timerId = null; }
    if ($('rs-result') && !$('rs-result').classList.contains('hidden')) {
      show('rs-result', false);
      show('rs-wiped', true);
    }
  }

  function save(bytes, name) {
    var url = URL.createObjectURL(new Blob([bytes], { type: 'application/x-pem-file' }));
    var a = document.createElement('a');
    a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
  }

  function slug(s) { return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'ap'; }

  async function run() {
    show('rs-error', false);
    if (!window.crypto || !crypto.subtle) { err('This browser does not provide WebCrypto (it needs HTTPS and a current browser).'); return; }
    var days = parseInt($('rs-days').value, 10) || 730;
    show('rs-form', false); show('rs-busy', true);
    try {
      var g = await generate($('rs-algo').value, app.dataset.ap);
      var body = new URLSearchParams({ csrf: app.dataset.csrf, csr: g.csrPem, days: String(days) });
      var resp = await fetch(app.dataset.signUrl, { method: 'POST', credentials: 'same-origin', body: body });
      var data = await resp.json();
      if (!resp.ok) throw new Error(data.error || ('server answered ' + resp.status));
      secret = { key: g.keyPem, cert: te.encode(data.cert), ca: te.encode(data.server_ca || '') };
      $('rs-ok').textContent = 'Certificate issued (serial ' + data.serial + ', valid until ' + data.not_after + ').';
      $('rs-ca-note').textContent = data.server_ca ? '' : 'The site’s server certificate has no CA chain on record (it was uploaded as a single certificate). Give the AP the CA that issued that certificate instead.';
      show('rs-busy', false); show('rs-result', true);
      deadline = Date.now() + TTL_MS;
      timerId = setInterval(function () {
        var left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
        $('rs-timer').textContent = 'The key is wiped automatically in ' + Math.floor(left / 60) + ':' + ('0' + (left % 60)).slice(-2);
        if (left <= 0) wipe();
      }, 500);
    } catch (e) {
      wipe();
      show('rs-busy', false); show('rs-form', true);
      err('Could not create the certificate: ' + e.message);
    }
  }

  var base = slug(app.dataset.ap);
  $('rs-go').addEventListener('click', run);
  $('rs-dl-key').addEventListener('click', function () { if (secret) save(secret.key, base + '-radsec.key.pem'); });
  $('rs-dl-cert').addEventListener('click', function () { if (secret) save(secret.cert, base + '-radsec.cert.pem'); });
  $('rs-dl-ca').addEventListener('click', function () { if (secret && secret.ca.length) save(secret.ca, 'server-ca.pem'); });
  $('rs-dl-all').addEventListener('click', function () {
    if (!secret) return;
    save(secret.key, base + '-radsec.key.pem');
    setTimeout(function () { if (secret) save(secret.cert, base + '-radsec.cert.pem'); }, 300);
    setTimeout(function () { if (secret && secret.ca.length) save(secret.ca, 'server-ca.pem'); }, 600);
  });
  $('rs-wipe').addEventListener('click', wipe);
  window.addEventListener('pagehide', wipe);
  document.addEventListener('visibilitychange', function () { if (document.hidden && secret) deadline = Math.min(deadline, Date.now() + 60 * 1000); });

  // exposed only for the automated browser self-test (page URL ending in #selftest)
  if (location.hash === '#selftest') window.__radsecTest = { generate: generate };
})();
