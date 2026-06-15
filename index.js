'use strict';

/**
 * 0cert-middleware
 * 
 * Drop-in Express middleware that adds 0Cert identity-based
 * encryption verification to any Node.js web server.
 * 
 * Usage:
 *   const zerocert = require('0cert-middleware')
 *   app.use(zerocert({
 *     identity: 'mysite.com',
 *     fullPrivKey: process.env.IBC_PRIV_KEY,
 *     userSecret: process.env.IBC_USER_SECRET,
 *     kgc: 'https://kgc.0cert.io'
 *   }))
 */

const crypto = require('crypto');
const https  = require('https');
const http   = require('http');

// ─── Default config ───────────────────────────────────────────────────────────

const DEFAULTS = {
  kgc:              'https://kgc.0cert.io',
  verifyPath:       '/.well-known/0cert',
  headerPrefix:     'X-0Cert',
  verifyOnStartup:  true,
  debug:            false,
};

// ─── Main middleware factory ──────────────────────────────────────────────────

function zerocert(options = {}) {
  const config = { ...DEFAULTS, ...options };

  // Validate required fields
  if (!config.identity) {
    throw new Error('[0cert] identity is required (e.g. "mysite.com")');
  }
  if (!config.fullPrivKey) {
    throw new Error('[0cert] fullPrivKey is required — get it from kgc.0cert.io or 0 Browser app');
  }
  if (!config.userSecret) {
    throw new Error('[0cert] userSecret is required — generated during key setup');
  }

  const normalized = config.identity.trim().toLowerCase();

  // State
  let kgcStatus     = 'pending';   // pending | verified | failed
  let publicParams  = null;
  let keyId         = null;
  let startupTime   = new Date().toISOString();

  // Verify with KGC on startup
  if (config.verifyOnStartup) {
    verifyWithKGC(config, normalized)
      .then(result => {
        kgcStatus    = 'verified';
        publicParams = result.publicParams;
        keyId        = result.keyId;
        log(config, `✅ 0Cert verified — identity: ${normalized}, keyId: ${keyId}`);
      })
      .catch(err => {
        kgcStatus = 'failed';
        log(config, `⚠️  0Cert KGC verification failed: ${err.message}`);
        log(config, '   Site will still serve but 0Cert badge may not show');
      });
  }

  // ─── The actual middleware ─────────────────────────────────────────────────

  return function zeroCertMiddleware(req, res, next) {

    // Serve /.well-known/0cert — browser calls this to verify the site
    if (req.path === config.verifyPath || req.url === config.verifyPath) {
      const payload = {
        ok:          true,
        version:     '1.0.0',
        identity:    normalized,
        kgc:         config.kgc,
        status:      kgcStatus,
        keyId:       keyId || 'pending',
        publicParams: publicParams || null,
        algorithm:   'CL-PKC-ECDH-v2',
        since:       startupTime,
        verifiedAt:  new Date().toISOString(),
      };

      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Access-Control-Allow-Origin', '*');
      addHeaders(res, config, normalized, kgcStatus);
      return res.json ? res.json(payload) : res.end(JSON.stringify(payload));
    }

    // Add 0Cert headers to all responses
    addHeaders(res, config, normalized, kgcStatus);

    next();
  };
}

// ─── Add security headers ─────────────────────────────────────────────────────

function addHeaders(res, config, identity, status) {
  const setHeader = res.setHeader
    ? (k, v) => res.setHeader(k, v)
    : (k, v) => { res[k] = v; };

  setHeader(`${config.headerPrefix}-Identity`,  identity);
  setHeader(`${config.headerPrefix}-KGC`,       config.kgc);
  setHeader(`${config.headerPrefix}-Status`,    status);
  setHeader(`${config.headerPrefix}-Version`,   '1.0.0');
  setHeader(`${config.headerPrefix}-Algorithm`, 'CL-PKC-ECDH-v2');
}

// ─── Verify with KGC ─────────────────────────────────────────────────────────

async function verifyWithKGC(config, identity) {
  // Check key status with KGC
  const statusResult = await kgcFetch(
    config.kgc,
    `/key/${encodeURIComponent(identity)}`,
    'GET'
  );

  if (!statusResult.ok) {
    throw new Error(`KGC returned error: ${statusResult.error || 'unknown'}`);
  }

  if (statusResult.status === 'revoked') {
    throw new Error(`Identity "${identity}" has been revoked`);
  }

  if (statusResult.status === 'not-issued') {
    throw new Error(
      `No key issued for "${identity}". ` +
      `Register at ${config.kgc} or use the 0 Browser app.`
    );
  }

  // Get public params
  const ppResult = await kgcFetch(config.kgc, '/public-params', 'GET');

  return {
    keyId:        statusResult.keyId,
    publicParams: ppResult.publicParams,
    issuedAt:     statusResult.issuedAt,
  };
}

// ─── Decrypt a message (utility function for app use) ────────────────────────

function decrypt(config, envelope) {
  const normalized = config.identity.trim().toLowerCase();

  if (!envelope || envelope.version !== 'cl-pkc-v2') {
    throw new Error('Invalid envelope — must be cl-pkc-v2 format from 0cert KGC');
  }

  if (envelope.identity !== normalized) {
    throw new Error(
      `Envelope encrypted for "${envelope.identity}", not "${normalized}"`
    );
  }

  // Reconstruct ECDH shared secret
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(config.userSecret, 'hex'));
  const sharedSecret = ecdh.computeSecret(
    Buffer.from(envelope.ephemeralPub, 'hex')
  );

  // Need public params for KGC binding — fetch synchronously from cache or use hint
  const ppHint = envelope.pp_hint;
  const kgcBinding = crypto.createHash('sha256')
    .update(envelope.pp_hint + '|cl-kgc-bind|' + normalized)
    .digest('hex');

  const sessionKey = crypto.createHash('sha256')
    .update('cl-session-v2|' + sharedSecret.toString('hex') + '|' + kgcBinding)
    .digest();

  const iv      = Buffer.from(envelope.iv, 'hex');
  const tag     = Buffer.from(envelope.tag, 'hex');
  const ct      = Buffer.from(envelope.ct, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
  decipher.setAuthTag(tag);

  try {
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    return plain.toString('utf8');
  } catch {
    throw new Error('Decryption failed — wrong keys or tampered envelope');
  }
}

// ─── Encrypt a message (utility function for app use) ────────────────────────

async function encrypt(kgcURL, identity, message) {
  const result = await kgcFetch(kgcURL, '/key/' + encodeURIComponent(identity), 'GET');

  if (result.status !== 'active') {
    throw new Error(`Cannot encrypt to "${identity}" — key status: ${result.status}`);
  }

  // Need userPublicCommitment — stored when key was issued
  // For server-to-server encryption, fetch from a public endpoint
  throw new Error(
    'Server-side encryption requires userPublicCommitment. ' +
    'Use POST /encrypt on the KGC directly with the recipient\'s public commitment.'
  );
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

function kgcFetch(baseURL, path, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const url      = new URL(path, baseURL);
    const isHttps  = url.protocol === 'https:';
    const lib      = isHttps ? https : http;

    const options = {
      hostname: url.hostname,
      port:     url.port || (isHttps ? 443 : 80),
      path:     url.pathname + url.search,
      method,
      headers: { 'Content-Type': 'application/json', 'User-Agent': '0cert-middleware/1.0.0' },
      timeout: 10000,
    };

    const bodyStr = body ? JSON.stringify(body) : null;
    if (bodyStr) options.headers['Content-Length'] = Buffer.byteLength(bodyStr);

    const req = lib.request(options, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error(`Invalid JSON from KGC: ${data.slice(0, 100)}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('KGC request timed out')); });
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// ─── Logger ──────────────────────────────────────────────────────────────────

function log(config, msg) {
  if (config.debug !== false) {
    console.log(`[0cert] ${msg}`);
  } else {
    // Always log startup messages
    if (msg.includes('✅') || msg.includes('⚠️')) {
      console.log(`[0cert] ${msg}`);
    }
  }
}

// ─── Exports ─────────────────────────────────────────────────────────────────

zerocert.decrypt = decrypt;
zerocert.encrypt = encrypt;
zerocert.version = '1.0.0';

module.exports = zerocert;
