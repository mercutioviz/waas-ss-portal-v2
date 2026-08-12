'use strict';
/**
 * Node.js test suite for the Config Transformer client-side logic.
 *
 * Run:
 *   cd /home/admin/waas-ss-portal
 *   python3 tests/js/generate_fixtures.py   # (re)generate fixtures from Python
 *   node tests/js/test_config_transformer.js
 */
const assert = require('assert');
const path   = require('path');

const { SECTION_DEFINITIONS, STRIP_CONSTANTS } = require('./constants.json');
const createTransformer = require('./config_transformer');
const fixtures = require('./fixtures.json');

const ct = createTransformer(SECTION_DEFINITIONS, STRIP_CONSTANTS);

// ---------------------------------------------------------------------------
// Minimal test harness (no external dependencies)
// ---------------------------------------------------------------------------
let passed = 0, failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓  ${name}`);
    passed++;
  } catch(err) {
    console.error(`  ✗  ${name}`);
    console.error(`     ${err.message}`);
    if (err.actual !== undefined) {
      console.error(`     actual:   ${JSON.stringify(err.actual)}`);
      console.error(`     expected: ${JSON.stringify(err.expected)}`);
    }
    failed++;
  }
}

function deepEqual(a, b) {
  assert.deepStrictEqual(a, b);
}

// ---------------------------------------------------------------------------
// PART 1 — Unit tests: buildSectionMetadata
// ---------------------------------------------------------------------------
console.log('\n=== buildSectionMetadata ===');

test('empty JSON → empty section list', () => {
  deepEqual(ct.buildSectionMetadata({}), []);
});

test('unknown keys are ignored', () => {
  const result = ct.buildSectionMetadata({ totally_unknown: { x: 1 } });
  deepEqual(result, []);
});

test('unknown key alongside known key: only known key returned', () => {
  const result = ct.buildSectionMetadata({
    unknown_key: {},
    url_protection: { enabled: true },
  });
  assert.strictEqual(result.length, 1);
  assert.strictEqual(result[0].key, 'url_protection');
});

test('simple section: correct metadata shape', () => {
  const result = ct.buildSectionMetadata({ url_protection: { enabled: true } });
  assert.strictEqual(result.length, 1);
  const sec = result[0];
  assert.strictEqual(sec.key,   'url_protection');
  assert.strictEqual(sec.type,  'simple');
  assert.strictEqual(sec.count, null);
  assert.ok(typeof sec.label === 'string' && sec.label.length > 0);
  assert.ok(typeof sec.description === 'string');
});

test('named_list (servers): count and item ids match input', () => {
  const servers = [
    { name: 'srv-a', host: '10.0.0.1' },
    { name: 'srv-b', host: '10.0.0.2' },
  ];
  const result = ct.buildSectionMetadata({ servers });
  assert.strictEqual(result[0].count, 2);
  assert.strictEqual(result[0].items[0].id,    'srv-a');
  assert.strictEqual(result[0].items[0].label, 'srv-a');
  assert.strictEqual(result[0].items[1].id,    'srv-b');
});

test('named_list: empty list → count=0, items=[]', () => {
  const result = ct.buildSectionMetadata({ servers: [] });
  assert.strictEqual(result[0].count, 0);
  deepEqual(result[0].items, []);
});

test('ip_list (allowed_ips): label joins ip+note', () => {
  const allowed_ips = [
    { ip: '1.2.3.4',     note: 'Partner' },
    { ip: '192.168.1.0', note: '' },           // empty note → just ip
    { ip: '10.0.0.0',    note: undefined },    // missing note → just ip
  ];
  const result = ct.buildSectionMetadata({ allowed_ips });
  assert.strictEqual(result[0].items[0].label, '1.2.3.4 — Partner');
  assert.strictEqual(result[0].items[1].label, '192.168.1.0');
  assert.strictEqual(result[0].items[2].label, '10.0.0.0');
});

test('subsection (client_evaluation): count from inner list_field', () => {
  const client_evaluation = {
    captcha_type: 'reCAPTCHA',
    rules: [{ name: 'rule1' }, { name: 'rule2' }],
  };
  const result = ct.buildSectionMetadata({ client_evaluation });
  assert.strictEqual(result[0].type,  'subsection');
  assert.strictEqual(result[0].count, 2);
  assert.strictEqual(result[0].items[0].id, 'rule1');
});

test('subsection: missing list_field → count=0', () => {
  const client_evaluation = { captcha_type: 'reCAPTCHA' };  // no 'rules' key
  const result = ct.buildSectionMetadata({ client_evaluation });
  assert.strictEqual(result[0].count, 0);
  deepEqual(result[0].items, []);
});

test('endpoints: sub_sections array present', () => {
  const endpoints = {
    https: { tls_12: true },
    advanced: { enable_http2: true },
    ports: [{ port: 443 }],
  };
  const result = ct.buildSectionMetadata({ endpoints });
  assert.strictEqual(result[0].type, 'endpoints');
  assert.ok(Array.isArray(result[0].sub_sections));
  assert.ok(result[0].sub_sections.length > 0);
});

test('endpoints: present=true for populated sub-sections', () => {
  const endpoints = { https: { tls_12: true }, ports: [{ port: 443 }] };
  const result = ct.buildSectionMetadata({ endpoints });
  const subs = Object.fromEntries(result[0].sub_sections.map(s => [s.key, s]));
  assert.strictEqual(subs.https.present,   true);
  assert.strictEqual(subs.ports.present,   true);
  assert.strictEqual(subs.advanced.present, false);  // not in input
});

test('endpoints: sni_certificates present=false when empty array', () => {
  const endpoints = { sni_certificates: [] };
  const result = ct.buildSectionMetadata({ endpoints });
  const sni = result[0].sub_sections.find(s => s.key === 'sni_certificates');
  assert.strictEqual(sni.present, false);
});

test('endpoints: sni_certificates present=true when array has items', () => {
  const endpoints = { sni_certificates: [{ domain: 'alt.example.com' }] };
  const result = ct.buildSectionMetadata({ endpoints });
  const sni = result[0].sub_sections.find(s => s.key === 'sni_certificates');
  assert.strictEqual(sni.present, true);
});

test('section order follows SECTION_DEFINITIONS order', () => {
  const config = { url_protection: {}, blocked_bots: {}, servers: [] };
  const result = ct.buildSectionMetadata(config);
  const keys = result.map(s => s.key);
  // servers comes before url_protection in SECTION_DEFINITIONS
  const serversIdx = keys.indexOf('servers');
  const urlIdx     = keys.indexOf('url_protection');
  assert.ok(serversIdx < urlIdx, `Expected servers (${serversIdx}) before url_protection (${urlIdx})`);
});

// ---------------------------------------------------------------------------
// PART 2 — Unit tests: filterItems
// ---------------------------------------------------------------------------
console.log('\n=== filterItems ===');

const ITEMS = [
  { name: 'alpha', value: 1 },
  { name: 'beta',  value: 2 },
  { name: 'gamma', value: 3 },
];

test('selectedIds=null → all items returned', () => {
  deepEqual(ct.filterItems(ITEMS, 'name', null), ITEMS);
});

test('selectedIds=undefined → all items returned', () => {
  deepEqual(ct.filterItems(ITEMS, 'name', undefined), ITEMS);
});

test('selectedIds=[] → empty result', () => {
  deepEqual(ct.filterItems(ITEMS, 'name', []), []);
});

test('selectedIds filters to matching items', () => {
  const result = ct.filterItems(ITEMS, 'name', ['alpha', 'gamma']);
  assert.strictEqual(result.length, 2);
  assert.strictEqual(result[0].name, 'alpha');
  assert.strictEqual(result[1].name, 'gamma');
});

test('selectedIds with non-matching value → item excluded', () => {
  const result = ct.filterItems(ITEMS, 'name', ['alpha', 'delta']);  // delta not in list
  assert.strictEqual(result.length, 1);
  assert.strictEqual(result[0].name, 'alpha');
});

test('numeric id field: String coercion matches string selectedId', () => {
  const items = [{ id: 1, val: 'a' }, { id: 2, val: 'b' }];
  const result = ct.filterItems(items, 'id', ['1']);  // string '1'
  assert.strictEqual(result.length, 1);
  assert.strictEqual(result[0].id, 1);
});

// ---------------------------------------------------------------------------
// PART 3 — Unit tests: joinLabel
// ---------------------------------------------------------------------------
console.log('\n=== joinLabel ===');

test('both fields present → joined with em dash', () => {
  assert.strictEqual(ct.joinLabel({ ip: '1.2.3.4', note: 'VPN' }, ['ip', 'note']), '1.2.3.4 — VPN');
});

test('second field empty string → only first field', () => {
  assert.strictEqual(ct.joinLabel({ ip: '1.2.3.4', note: '' }, ['ip', 'note']), '1.2.3.4');
});

test('second field null → only first field', () => {
  assert.strictEqual(ct.joinLabel({ ip: '1.2.3.4', note: null }, ['ip', 'note']), '1.2.3.4');
});

test('second field missing → only first field', () => {
  assert.strictEqual(ct.joinLabel({ ip: '1.2.3.4' }, ['ip', 'note']), '1.2.3.4');
});

test('all fields missing → (unnamed)', () => {
  assert.strictEqual(ct.joinLabel({}, ['ip', 'note']), '(unnamed)');
});

test('more than two fields → only first two joined', () => {
  const label = ct.joinLabel({ a: 'x', b: 'y', c: 'z' }, ['a', 'b', 'c']);
  assert.strictEqual(label, 'x — y');  // c is dropped
});

// ---------------------------------------------------------------------------
// PART 4 — Unit tests: doTransform
// ---------------------------------------------------------------------------
console.log('\n=== doTransform ===');

test('include=false → section omitted from result', () => {
  const config = { url_protection: { enabled: true } };
  const result = ct.doTransform(config, { url_protection: { include: false } });
  deepEqual(result, {});
});

test('all sections excluded → empty result', () => {
  const config = { url_protection: { enabled: true }, blocked_bots: { scanners: true } };
  const result = ct.doTransform(config, {
    url_protection: { include: false },
    blocked_bots:   { include: false },
  });
  deepEqual(result, {});
});

test('simple section: full copy, value unchanged', () => {
  const val = { enabled: true, max_url_length: 8192, csrf: { enabled: false } };
  const result = ct.doTransform(
    { url_protection: val },
    { url_protection: { include: true } }
  );
  deepEqual(result.url_protection, val);
});

test('named_list: items=null → all items returned', () => {
  const servers = [{ name: 'srv1', host: 'h1' }, { name: 'srv2', host: 'h2' }];
  const result = ct.doTransform({ servers }, { servers: { include: true, items: null } });
  assert.strictEqual(result.servers.length, 2);
});

test('named_list: SERVER_RUNTIME_STRIP fields removed', () => {
  const servers = [{
    name: 'srv1',
    host: 'h1',
    health: 'up',
    mode: 'active',
    backend_test_result: 'ok',
    viewed_backend_result: true,
    last_test_time: 1700000000,
    testing_backend_connectivity: false,
    ssl_to_backend: false,
  }];
  const result = ct.doTransform({ servers }, { servers: { include: true, items: null } });
  const s = result.servers[0];
  assert.ok(!('health'  in s), 'health should be stripped');
  assert.ok(!('mode'    in s), 'mode should be stripped');
  assert.ok(!('backend_test_result' in s), 'backend_test_result should be stripped');
  assert.ok(!('viewed_backend_result' in s), 'viewed_backend_result should be stripped');
  assert.ok(!('last_test_time' in s), 'last_test_time should be stripped');
  assert.ok(!('testing_backend_connectivity' in s), 'testing_backend_connectivity should be stripped');
  assert.ok('name' in s, 'name should be kept');
  assert.ok('host' in s, 'host should be kept');
  assert.ok('ssl_to_backend' in s, 'ssl_to_backend should be kept');
});

test('named_list: filtered by items list', () => {
  const servers = [
    { name: 'srv1', host: 'h1' },
    { name: 'srv2', host: 'h2' },
    { name: 'srv3', host: 'h3' },
  ];
  const result = ct.doTransform({ servers }, { servers: { include: true, items: ['srv1', 'srv3'] } });
  assert.strictEqual(result.servers.length, 2);
  assert.strictEqual(result.servers[0].name, 'srv1');
  assert.strictEqual(result.servers[1].name, 'srv3');
});

test('ip_list: items=null → all IPs kept', () => {
  const allowed_ips = [{ ip: '1.1.1.1', note: 'A' }, { ip: '2.2.2.2', note: 'B' }];
  const result = ct.doTransform({ allowed_ips }, { allowed_ips: { include: true, items: null } });
  assert.strictEqual(result.allowed_ips.length, 2);
  deepEqual(result.allowed_ips, allowed_ips);
});

test('ip_list: filtered by ip address', () => {
  const allowed_ips = [{ ip: '1.1.1.1', note: 'A' }, { ip: '2.2.2.2', note: 'B' }];
  const result = ct.doTransform({ allowed_ips }, { allowed_ips: { include: true, items: ['2.2.2.2'] } });
  assert.strictEqual(result.allowed_ips.length, 1);
  assert.strictEqual(result.allowed_ips[0].ip, '2.2.2.2');
});

test('subsection: items=null → all rules kept, non-list fields preserved', () => {
  const client_evaluation = { captcha_type: 'rc', rules: [{ name: 'r1' }, { name: 'r2' }] };
  const result = ct.doTransform({ client_evaluation }, { client_evaluation: { include: true, items: null } });
  assert.strictEqual(result.client_evaluation.captcha_type, 'rc');
  assert.strictEqual(result.client_evaluation.rules.length, 2);
});

test('subsection: filtered items, non-list fields still present', () => {
  const client_evaluation = { captcha_type: 'rc', rules: [{ name: 'r1' }, { name: 'r2' }, { name: 'r3' }] };
  const result = ct.doTransform({ client_evaluation }, { client_evaluation: { include: true, items: ['r1', 'r3'] } });
  assert.strictEqual(result.client_evaluation.captcha_type, 'rc');
  assert.strictEqual(result.client_evaluation.rules.length, 2);
  assert.strictEqual(result.client_evaluation.rules[0].name, 'r1');
  assert.strictEqual(result.client_evaluation.rules[1].name, 'r3');
});

test('subsection: items=[] → empty list_field, non-list fields preserved', () => {
  const client_evaluation = { captcha_type: 'rc', rules: [{ name: 'r1' }] };
  const result = ct.doTransform({ client_evaluation }, { client_evaluation: { include: true, items: [] } });
  assert.strictEqual(result.client_evaluation.captcha_type, 'rc');
  deepEqual(result.client_evaluation.rules, []);
});

// ---------------------------------------------------------------------------
// PART 5 — Unit tests: endpoints / transformEndpoints
// ---------------------------------------------------------------------------
console.log('\n=== transformEndpoints ===');

const EP = {
  https:      { tls_12: true, tls_13: true },
  advanced:   { enable_http2: true },
  deployment: { primary_region: 'westus' },
  domains:    ['example.com'],
  sni_certificates: [{ domain: 'alt.example.com' }],
  ports: [
    {
      port: 443,
      protocol: 'HTTPS',
      ca_name: 'Let\'s Encrypt',
      waf_container_exposed_port: 32768,
      advanced_configuration: { session_timeout: 60 },
    },
  ],
  certificate: {
    ssl_certificate:                  'CERT_PEM',
    encrypted_ssl_private_key:        'ENC_KEY',
    aes_key_encrypted:                'AES_ENC',
    aes_key_customer_container:       'AES_CC',
    ssl_private_key_customer_container: 'PK_CC',
    use_automatic:                    true,
    enable_container_secret:          false,
  },
};

test('only https selected → result has only https', () => {
  const result = ct.transformEndpoints(EP, { https: true });
  assert.ok('https' in result);
  assert.ok(!('advanced'   in result));
  assert.ok(!('ports'      in result));
  assert.ok(!('certificate' in result));
  deepEqual(result.https, EP.https);
});

test('only advanced selected → result has only advanced', () => {
  const result = ct.transformEndpoints(EP, { advanced: true });
  assert.ok('advanced' in result);
  assert.ok(!('https' in result));
});

test('ports selected → ca_name and waf_container_exposed_port stripped', () => {
  const result = ct.transformEndpoints(EP, { ports: true });
  assert.ok('ports' in result);
  const port = result.ports[0];
  assert.ok(!('ca_name'                  in port), 'ca_name should be stripped');
  assert.ok(!('waf_container_exposed_port' in port), 'waf_container_exposed_port should be stripped');
  assert.ok('port' in port,                          'port should be kept');
  assert.ok('protocol' in port,                      'protocol should be kept');
  assert.ok('advanced_configuration' in port,        'advanced_configuration should be kept');
});

test('certificate selected → encrypted fields stripped, use_automatic kept', () => {
  const result = ct.transformEndpoints(EP, { certificate: true });
  assert.ok('certificate' in result);
  const cert = result.certificate;
  const alwaysStrip = STRIP_CONSTANTS.endpoint_cert;
  for (const field of alwaysStrip) {
    assert.ok(!(field in cert), `${field} should be stripped`);
  }
  assert.ok('use_automatic'          in cert, 'use_automatic should be kept');
  assert.ok('enable_container_secret' in cert, 'enable_container_secret should be kept');
});

test('sni_certificates selected → array copied', () => {
  const result = ct.transformEndpoints(EP, { sni_certificates: true });
  deepEqual(result.sni_certificates, EP.sni_certificates);
});

test('no subs selected → empty result (section omitted from doTransform output)', () => {
  const result = ct.transformEndpoints(EP, {});
  deepEqual(result, {});
  // When transformEndpoints returns {}, doTransform does NOT add endpoints to result
  const config = { endpoints: EP };
  const transformed = ct.doTransform(config, { endpoints: { include: true, sub: {} } });
  assert.ok(!('endpoints' in transformed));
});

test('all subs selected → all sub-sections present', () => {
  const allSub = { https: true, advanced: true, ports: true, certificate: true,
                   deployment: true, domains: true, sni_certificates: true };
  const result = ct.transformEndpoints(EP, allSub);
  assert.ok('https'            in result);
  assert.ok('advanced'         in result);
  assert.ok('ports'            in result);
  assert.ok('certificate'      in result);
  assert.ok('deployment'       in result);
  assert.ok('domains'          in result);
  assert.ok('sni_certificates' in result);
});

// ---------------------------------------------------------------------------
// PART 6 — Cross-validation against Python fixtures
// ---------------------------------------------------------------------------
console.log('\n=== Cross-validation vs Python ===');

for (const fixture of fixtures) {
  // Parse cross-validation
  test(`[${fixture.name}] buildSectionMetadata matches Python`, () => {
    const jsResult = ct.buildSectionMetadata(fixture.config);
    deepEqual(jsResult, fixture.expected_sections);
  });

  // Transform cross-validation (only fixtures with selections defined)
  if (fixture.selections !== null) {
    test(`[${fixture.name}] doTransform matches Python`, () => {
      const jsResult = ct.doTransform(fixture.config, fixture.selections);
      deepEqual(jsResult, fixture.expected_transform);
    });
  }
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
const total = passed + failed;
console.log(`\n${'─'.repeat(50)}`);
console.log(`Results: ${passed}/${total} passed${failed > 0 ? `, ${failed} FAILED` : ''}`);
if (failed > 0) process.exit(1);
