const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');process.env.DATA_DIR=require('node:path').join(require('node:os').tmpdir(),'atlas-test-'+process.pid);const {server,ipAllowed,validTotp,totp,esc}=require('../server');
test('IP allowlist uses exact matches and does not admit prefixes',()=>{assert.equal(ipAllowed('1.2.3.4','1.2.3.4,5.6.7.8'),true);assert.equal(ipAllowed('1.2.3.45','1.2.3.4'),false)});
test('TOTP rejects bad formats and validates current code',()=>{const key='JBSWY3DPEHPK3PXP';assert.equal(validTotp('123',key),false);assert.equal(validTotp(totp(key,Math.floor(Date.now()/30000)),key),true)});
test('HTML escaping prevents markup injection',()=>assert.equal(esc('<script>"&'), '&lt;script&gt;&quot;&amp;'));
test('Unauthorized request cannot enter protected workspace',async()=>{process.env.ALLOWED_IPS='127.0.0.1,::1';await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;const response=await fetch(base+'/dashboard');assert.equal(response.status,200);assert.match(await response.text(),/Welcome back\./);const b=await fetch(base+'/websites/create',{method:'POST'});assert.equal(b.status,401);const css=await fetch(base+'/assets/style.css');assert.equal(css.status,200);server.close()});
const {remoteIP,privateProxy}=require('../server');
test('proxy mode resolves rightmost forwarded IP only from private peer',()=>{process.env.TRUST_RAILWAY_PROXY='1';assert.equal(remoteIP({socket:{remoteAddress:'10.5.0.2'},headers:{'x-forwarded-for':'6.6.6.6, 103.52.212.102'}}),'103.52.212.102');assert.equal(remoteIP({socket:{remoteAddress:'8.8.8.8'},headers:{'x-forwarded-for':'103.52.212.102'}}),'8.8.8.8');delete process.env.TRUST_RAILWAY_PROXY});
test('quoted allowlist values are normalized',()=>{assert.equal(ipAllowed('103.52.212.102','"103.52.212.102"'),true);assert.equal(privateProxy('10.0.0.1'),true);assert.equal(privateProxy('8.8.8.8'),false)});

// Regression: an extra upstream hop was causing Railway to identify its proxy instead of the visitor.
test('Railway chained proxy yields verified visitor while refusing spoofed left prefixes',()=>{
  process.env.TRUST_RAILWAY_PROXY='1';
  process.env.TRUSTED_UPSTREAM_IPS='152.233.68.105';
  const req=(xff,peer='100.64.0.1')=>({socket:{remoteAddress:peer},headers:{'x-forwarded-for':xff}});
  assert.equal(remoteIP(req('103.52.212.102, 152.233.68.105')),'103.52.212.102');
  assert.equal(remoteIP(req('103.52.212.102, 198.51.100.44, 152.233.68.105')),'198.51.100.44');
  assert.equal(remoteIP(req('103.52.212.102, 152.233.68.105','8.8.8.8')),'8.8.8.8');
  assert.equal(remoteIP(req('garbage, 152.233.68.105')),'100.64.0.1');
  delete process.env.TRUSTED_UPSTREAM_IPS;delete process.env.TRUST_RAILWAY_PROXY;
});
