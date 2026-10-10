import base64, http.client, os, re, tempfile, threading, unittest
from cryptography.fernet import Fernet
from security import hash_password, totp, verify_password
import app

class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.password='Strong-Test-Password-123'
        cls.secret=base64.b32encode(b'12345678901234567890').decode()
        os.environ.update(ADMIN_USERNAME='admin',ADMIN_PASSWORD_HASH=hash_password(cls.password),ADMIN_TOTP_SECRET=cls.secret,ENCRYPTION_KEY=Fernet.generate_key().decode(),APP_URL='http://localhost',DATA_DIR=cls.temp.name,COOKIE_SECURE='false')
        app.initialize()
        cls.server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.temp.cleanup()
    def request(self,path,method='GET',data=None,cookie='',origin=None):
        from urllib.parse import urlencode
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        request_headers={'Cookie':cookie,'Content-Type':'application/x-www-form-urlencoded'}
        if origin:
            request_headers['Origin']=origin
        connection.request(method,path,urlencode(data) if data is not None else None,request_headers)
        response=connection.getresponse(); body=response.read().decode(); headers=dict(response.getheaders()); status=response.status
        connection.close()
        return status,body,headers
    def test_flow(self):
        self.assertEqual(self.request('/health')[0],200)
        self.assertEqual(self.request('/')[0],303)
        status,body,headers=self.request('/login')
        self.assertEqual(status,200)
        cookie=headers['Set-Cookie'].split(';')[0]
        csrf=re.search('name="csrf" value="([^"]+)"',body)[1]
        self.assertEqual(self.request('/login','POST',{'csrf':'wrong'},cookie)[0],403)
        self.assertEqual(self.request('/login','POST',{'csrf':csrf,'username':'admin','password':'wrong','otp':'123456'},cookie)[0],401)
        self.assertEqual(self.request('/login','POST',{'csrf':csrf,'username':'admin','password':self.password},cookie,origin='https://attacker.example')[0],403)
        status,_,headers=self.request('/login','POST',{'csrf':csrf,'username':'admin','password':self.password},cookie,origin='http://LOCALHOST:80')
        self.assertEqual(status,303)
        self.assertEqual(headers['Location'],'/2fa')
        pending=headers['Set-Cookie'].split(';')[0]
        self.assertEqual(self.request('/',cookie=pending)[0],303)
        self.assertEqual(self.request('/2fa/qr',cookie=cookie)[0],303)
        _,body,_=self.request('/2fa',cookie=pending)
        self.assertIn('/2fa/qr',body)
        self.assertIn(self.secret,body)
        qr_status,qr_body,_=self.request('/2fa/qr',cookie=pending)
        self.assertEqual(qr_status,200)
        self.assertIn('<svg',qr_body)
        pending_csrf=re.search('name="csrf" value="([^"]+)"',body)[1]
        self.assertEqual(self.request('/websites/save','POST',{'csrf':pending_csrf},pending)[0],403)
        self.assertEqual(self.request('/2fa','POST',{'csrf':pending_csrf,'otp':'invalid'},pending)[0],401)
        status,_,headers=self.request('/2fa','POST',{'csrf':pending_csrf,'otp':totp(self.secret)},pending)
        self.assertEqual(status,303)
        authenticated=headers['Set-Cookie'].split(';')[0]
        self.assertNotEqual(authenticated,cookie)
        self.assertEqual(self.request('/websites',cookie=cookie)[0],303)
        _,body,_=self.request('/websites',cookie=authenticated)
        csrf=re.search('name="csrf" value="([^"]+)"',body)[1]
        data={'csrf':csrf,'code':'WEB01','name':'<script>alert(1)</script>','url':'https://example.com/','credential':'session-secret'}
        self.assertEqual(self.request('/websites/save','POST',data,authenticated)[0],303)
        body=self.request('/websites',cookie=authenticated)[1]
        self.assertIn('&lt;script&gt;',body); self.assertNotIn('session-secret',body)
        with app.connect() as db:
            stored=db.execute('SELECT credential FROM websites').fetchone()[0]
        self.assertNotIn('session-secret',stored)
        self.assertEqual(app.cipher(app.ENV['ENCRYPTION_KEY']).decrypt(stored.encode()).decode(),'session-secret')
        report={'csrf':csrf,'website_id':'1','market':'BRUNEI','period':'2310','number':'0012','revenue':'100000','payout':'80000','invoices':'3','source':'https://example.com/result','status':'VERIFIED'}
        self.assertEqual(self.request('/reports/save','POST',report,authenticated)[0],303)
        self.assertIn('0012',self.request('/reports',cookie=authenticated)[1])
        report['number']='12'
        self.assertEqual(self.request('/reports/save','POST',report,authenticated)[0],400)
        self.assertEqual(self.request('/websites/delete','POST',{'csrf':csrf,'id':'1'},authenticated)[0],400)
        self.assertIn('20000',self.request('/',cookie=authenticated)[1])
        self.assertIn('0012',self.request('/export',cookie=authenticated)[1])
        self.assertIn('REPORT_SAVED',self.request('/audit',cookie=authenticated)[1])
        self.assertEqual(self.request('/logout','POST',{'csrf':csrf},authenticated)[0],303)
        self.assertEqual(self.request('/',cookie=authenticated)[0],303)
        _,body,headers=self.request('/login')
        cookie=headers['Set-Cookie'].split(';')[0]
        csrf=re.search('name="csrf" value="([^"]+)"',body)[1]
        _,_,headers=self.request('/login','POST',{'csrf':csrf,'username':'admin','password':self.password},cookie)
        pending=headers['Set-Cookie'].split(';')[0]
        body=self.request('/2fa',cookie=pending)[1]
        self.assertNotIn('/2fa/qr',body)
        self.assertNotIn(self.secret,body)
        self.assertEqual(self.request('/2fa/qr',cookie=pending)[0],404)
    def test_password_and_totp(self):
        self.assertTrue(verify_password(self.password,os.environ['ADMIN_PASSWORD_HASH']))
        self.assertFalse(verify_password('wrong',os.environ['ADMIN_PASSWORD_HASH']))
        self.assertEqual(totp(self.secret,1),'287082')
    def test_origin_normalization(self):
        self.assertEqual(app.normalize_origin(' "https://EXAMPLE.com:443/" '),app.normalize_origin('https://example.com'))
        self.assertNotEqual(app.normalize_origin('http://example.com'),app.normalize_origin('https://example.com'))
        with self.assertRaises(ValueError):
            app.normalize_origin('null')

if __name__=='__main__': unittest.main(verbosity=2)
