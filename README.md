# 0cert-middleware

> Drop-in Express middleware for [0Cert](https://0cert.io) — identity-based encryption for Node.js.  
> Zero certificates. Zero renewals. Zero CAs.

---

## Install

```bash
npm install 0cert-middleware
```

## Usage

```javascript
const express   = require('express')
const zerocert  = require('0cert-middleware')

const app = express()

app.use(zerocert({
  identity:    'mysite.com',               // your domain
  fullPrivKey: process.env.IBC_PRIV_KEY,   // from 0 Browser app or KGC API
  userSecret:  process.env.IBC_USER_SECRET, // generated during key setup
  kgc:         'https://kgc.0cert.io'      // public KGC (or your own)
}))

app.get('/', (req, res) => {
  res.send('Hello! This site is 0Cert protected.')
})

app.listen(3000)
```

That's it. Your site now:
- Serves `/.well-known/0cert` — verified by 0 Browser automatically
- Adds `X-0Cert-*` headers to all responses
- Shows **0Cert Verified** badge to 0 Browser users

---

## Get your keys

**Option 1 — 0 Browser app (easiest)**
1. Download 0 Browser on iOS
2. Go to My Sites tab → tap +
3. Enter your domain
4. Copy the keys shown

**Option 2 — KGC API directly**
```bash
# 1. Generate user secret
curl -X POST https://kgc.0cert.io/user/generate-secret

# 2. Issue partial key for your domain
curl -X POST https://kgc.0cert.io/issue-partial-key \
  -H "Content-Type: application/json" \
  -d '{"identity": "mysite.com"}'

# 3. Combine keys
curl -X POST https://kgc.0cert.io/user/combine-keys \
  -H "Content-Type: application/json" \
  -d '{
    "identity": "mysite.com",
    "partialKey": "...",
    "userSecret": "..."
  }'
```

Store the keys as environment variables:
```bash
IBC_PRIV_KEY=your_full_priv_key
IBC_USER_SECRET=your_user_secret
```

---

## Add DNS TXT record

In your domain registrar, add:
```
TXT  @  ibc-kgc=https://kgc.0cert.io
```

This tells 0 Browser which KGC to use for your domain.

---

## Options

```javascript
zerocert({
  // Required
  identity:    'mysite.com',
  fullPrivKey: '...',
  userSecret:  '...',

  // Optional
  kgc:              'https://kgc.0cert.io', // KGC server URL
  verifyPath:       '/.well-known/0cert',   // verification endpoint path
  verifyOnStartup:  true,                   // verify with KGC on startup
  debug:            false,                  // verbose logging
})
```

---

## Verification endpoint

The middleware automatically serves `/.well-known/0cert`:

```json
{
  "ok": true,
  "version": "1.0.0",
  "identity": "mysite.com",
  "kgc": "https://kgc.0cert.io",
  "status": "verified",
  "keyId": "...",
  "algorithm": "CL-PKC-ECDH-v2"
}
```

0 Browser calls this endpoint when visiting your site to show the verified badge.

---

## Response headers

Added to every response:

```
X-0Cert-Identity:  mysite.com
X-0Cert-KGC:       https://kgc.0cert.io
X-0Cert-Status:    verified
X-0Cert-Version:   1.0.0
X-0Cert-Algorithm: CL-PKC-ECDH-v2
```

---

## Decrypt messages (optional)

If you receive encrypted messages via the 0Cert protocol:

```javascript
const zerocert = require('0cert-middleware')

const config = {
  identity:    'mysite.com',
  fullPrivKey: process.env.IBC_PRIV_KEY,
  userSecret:  process.env.IBC_USER_SECRET,
}

// Decrypt an envelope received from a 0Cert client
const plaintext = zerocert.decrypt(config, envelope)
console.log(plaintext) // → original message
```

---

## Enterprise / private KGC

Point to your own KGC server:

```javascript
app.use(zerocert({
  identity:    'mysite.com',
  fullPrivKey: process.env.IBC_PRIV_KEY,
  userSecret:  process.env.IBC_USER_SECRET,
  kgc:         'https://kgc.yourcompany.com', // private KGC
}))
```

See [github.com/0cert/kgc-server](https://github.com/0cert/kgc-server) to self-host.

---

## How it works

```
Traditional SSL:
  CA signs certificate → browsers trust ~150 CAs → encrypted connection
  Problem: any CA can fake any certificate

0Cert (CL-PKC):
  KGC issues partial key → you generate user secret → combined = full key
  Encryption uses ECDH P-256 against your public key
  Even the KGC cannot decrypt your traffic
```

→ [Read more at 0cert.io](https://0cert.io)

---

## License

MIT — [0cert.io](https://0cert.io)
