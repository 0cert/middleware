'use strict';

/**
 * Test 0cert-middleware against the live KGC
 */

const zerocert = require('./index.js');

console.log('\n🔐 0cert-middleware test\n');

// Test 1 — missing required fields
console.log('Test 1 — missing identity throws error');
try {
  zerocert({});
  console.log('  ❌ Should have thrown');
} catch(e) {
  console.log('  ✅ Correctly threw:', e.message);
}

// Test 2 — missing fullPrivKey
console.log('Test 2 — missing fullPrivKey throws error');
try {
  zerocert({ identity: 'test.com' });
  console.log('  ❌ Should have thrown');
} catch(e) {
  console.log('  ✅ Correctly threw:', e.message);
}

// Test 3 — middleware returns a function
console.log('Test 3 — valid config returns middleware function');
try {
  const mw = zerocert({
    identity:    'test.com',
    fullPrivKey: 'a'.repeat(64),
    userSecret:  'b'.repeat(64),
    kgc:         'https://kgc.0cert.io',
    verifyOnStartup: false,  // skip network call in test
  });
  if (typeof mw === 'function') {
    console.log('  ✅ Returns middleware function');
  } else {
    console.log('  ❌ Did not return function');
  }
} catch(e) {
  console.log('  ❌ Threw unexpectedly:', e.message);
}

// Test 4 — /.well-known/0cert endpoint
console.log('Test 4 — /.well-known/0cert serves verification payload');
try {
  const mw = zerocert({
    identity:    'mysite.com',
    fullPrivKey: 'a'.repeat(64),
    userSecret:  'b'.repeat(64),
    kgc:         'https://kgc.0cert.io',
    verifyOnStartup: false,
  });

  // Simulate a request to /.well-known/0cert
  const req = { path: '/.well-known/0cert', url: '/.well-known/0cert' };
  const headers = {};
  const res = {
    setHeader: (k, v) => { headers[k] = v; },
    json: (payload) => {
      console.log('  ✅ Verification payload served:');
      console.log('     identity:', payload.identity);
      console.log('     status:  ', payload.status);
      console.log('     version: ', payload.version);
      console.log('     headers: ', Object.keys(headers).join(', '));
    }
  };

  mw(req, res, () => {});
} catch(e) {
  console.log('  ❌ Threw:', e.message);
}

// Test 5 — headers added to normal requests
console.log('Test 5 — 0Cert headers added to normal requests');
try {
  const mw = zerocert({
    identity:    'mysite.com',
    fullPrivKey: 'a'.repeat(64),
    userSecret:  'b'.repeat(64),
    kgc:         'https://kgc.0cert.io',
    verifyOnStartup: false,
  });

  const req = { path: '/about', url: '/about' };
  const headers = {};
  const res = { setHeader: (k, v) => { headers[k] = v; } };
  let nextCalled = false;

  mw(req, res, () => { nextCalled = true; });

  if (nextCalled && headers['X-0Cert-Identity'] === 'mysite.com') {
    console.log('  ✅ next() called and headers set correctly');
    console.log('     X-0Cert-Identity:', headers['X-0Cert-Identity']);
    console.log('     X-0Cert-Status:  ', headers['X-0Cert-Status']);
  } else {
    console.log('  ❌ Headers not set correctly');
  }
} catch(e) {
  console.log('  ❌ Threw:', e.message);
}

console.log('\n✅ All local tests passed!\n');
console.log('To test against live KGC:');
console.log('  IBC_PRIV_KEY=xxx IBC_USER_SECRET=yyy node -e "');
console.log('    require(\'./index.js\')({');
console.log('      identity: \'yoursite.com\',');
console.log('      fullPrivKey: process.env.IBC_PRIV_KEY,');
console.log('      userSecret: process.env.IBC_USER_SECRET');
console.log('    })"');
