'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'atlas-vault-'));
process.env.DATA_DIR=dir;
process.env.SESSION_CREDENTIAL_KEY='11'.repeat(32);
const {sessionVaultStatus}=require('../server');
function ciphertext(value){const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',Buffer.from(process.env.SESSION_CREDENTIAL_KEY,'hex'),iv);const out=Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);return [iv.toString('hex'),cipher.getAuthTag().toString('hex'),out.toString('hex')].join('.')}
test('vault differentiates missing, authentic and modified session ciphertext',()=>{
 assert.equal(sessionVaultStatus({}),'none');
 const original=ciphertext('session=abc');
 assert.equal(sessionVaultStatus({encryptedSession:original}),'intact');
 const parts=original.split('.');parts[2]=parts[2].replace(/^../,parts[2].startsWith('aa')?'bb':'aa');
 assert.equal(sessionVaultStatus({encryptedSession:parts.join('.')}),'invalid');
 assert.equal(sessionVaultStatus({encryptedSession:'bad'}),'invalid');
});
test('vault refuses to call an unreadable session valid when encryption key missing',()=>{
 const enc=ciphertext('token=xyz');
 delete process.env.SESSION_CREDENTIAL_KEY;
 assert.equal(sessionVaultStatus({encryptedSession:enc}),'key_missing');
});
