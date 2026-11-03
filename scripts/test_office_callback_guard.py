import base64
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import types
import unittest
import sqlite3
import tempfile
from unittest.mock import patch

# Execute source without importing into the resource tree or generating packaged bytecode.
g=types.ModuleType('office_callback_guard');exec(compile((Path(__file__).parents[1]/'src/main/resources/runtime/office-callback-guard.py').read_text(),'office-callback-guard.py','exec'),g.__dict__)
SECRET='a'*64
PAYLOAD={'key':'fixture-key','status':6,'url':'https://office:8443/cache/files/fixture/output.docx?expires=2000&md5=signature'}

def token(payload=PAYLOAD,**extra):
    claims={'payload':payload,'operation':'callback','iat':1000,'exp':1300};claims.update(extra)
    encode=lambda value:base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
    text=encode({'alg':'HS256','typ':'JWT'})+'.'+encode(claims)
    return 'Bearer '+text+'.'+base64.urlsafe_b64encode(hmac.new(SECRET.encode(),text.encode(),hashlib.sha256).digest()).decode().rstrip('=')

class CallbackGuardTest(unittest.TestCase):
    def test_signed_body_and_bounded_lifetime_required(self):
        key,ttl=g.validate_callback(token(),json.dumps(PAYLOAD).encode(),SECRET,1100)
        self.assertTrue(key.startswith('office-callback-v2:'));self.assertEqual(ttl,200)
        for header,body in [('',PAYLOAD),(token()[:-1]+'x',PAYLOAD),(token(exp=1099),PAYLOAD),(token(iat=1200),PAYLOAD),(token(exp=2000),PAYLOAD),(token(exp=True),PAYLOAD),(token(),{**PAYLOAD,'status':4}),(token(payload=None),PAYLOAD)]:
            with self.subTest(header=header[:10]),self.assertRaises(ValueError):g.validate_callback(header,json.dumps(body).encode(),SECRET,1100)

    def test_native_ce10_body_envelope_and_purpose_are_verified(self):
        claims={**PAYLOAD,'operation':'callback','iat':1000,'exp':1300}
        encode=lambda value:base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
        signed=encode({'alg':'HS256'})+'.'+encode(claims)
        native=signed+'.'+base64.urlsafe_b64encode(hmac.new(SECRET.encode(),signed.encode(),hashlib.sha256).digest()).decode().rstrip('=')
        body={**PAYLOAD,'token':native}
        g.validate_callback('',json.dumps(body).encode(),SECRET,1100)
        with self.assertRaises(ValueError):g.validate_callback('',json.dumps({**body,'status':4}).encode(),SECRET,1100)
        with self.assertRaises(ValueError):g.validate_callback(token(operation='convert'),json.dumps(PAYLOAD).encode(),SECRET,1100)
        typed={**PAYLOAD,'history':{'version':1}}
        with self.assertRaises(ValueError):g.validate_callback(token(typed),json.dumps({**typed,'history':{'version':True}}).encode(),SECRET,1100)

    def test_download_origin_traversal_and_duplicate_fields_denied(self):
        for url in ['http://office:8443/cache/files/a','https://evil.invalid/cache/files/a','https://office:8443/internal/a','https://office:8443/cache/files/%2e%2e/a','https://user@office:8443/cache/files/a','https://office:8443/cache/files/a#secret']:
            body={**PAYLOAD,'url':url}
            with self.subTest(url=url),self.assertRaises(ValueError):g.validate_callback(token(body),json.dumps(body).encode(),SECRET,1100)
        with self.assertRaises(ValueError):g.unique_object([('key',1),('key',2)])
        with self.assertRaises(ValueError):g.validate_callback(token(),b'x'*1048577,SECRET,1100)
        with self.assertRaises(ValueError):g.validate_callback(token(),json.dumps(PAYLOAD).encode(),'short',1100)

    def test_browser_scope_and_invalid_document_metadata_denied(self):
        for payload in [{'document':{'key':'fixture-key'}},{**PAYLOAD,'key':'../path'},{**PAYLOAD,'status':True},{**PAYLOAD,'status':99},{'key':'fixture-key','status':2}]:
            with self.assertRaises(ValueError):g.validate_callback(token(payload),json.dumps(payload).encode(),SECRET,1100)
        for status in (1,4):
            payload={'key':'fixture-key','status':status};g.validate_callback(token(payload),json.dumps(payload).encode(),SECRET,1100)

    def test_completed_duplicate_is_idempotent_and_uncertain_write_not_replayed(self):
        values={};calls=[]
        class Ledger:
            def reserve(self,k,expires):
                if k in values:return values[k]
                values[k]='pending';return 'new'
            def complete(self,k):values[k]='done'
        class Response:
            def __init__(self,data,status=200):self.content=json.dumps(data).encode();self.status_code=status
        modules={'django.conf':types.SimpleNamespace(settings=types.SimpleNamespace(ONLYOFFICE_JWT_SECRET=SECRET)),'django.http':types.SimpleNamespace(JsonResponse=Response)}
        request=types.SimpleNamespace(path='/onlyoffice/editor-callback/',method='POST',headers={'Authorization':token()},body=json.dumps(PAYLOAD).encode())
        def native(r):calls.append(r);return Response({'error':0})
        with patch.dict('sys.modules',modules),patch.object(g.time,'time',return_value=1100),patch.object(g,'CallbackLedger',Ledger):
            guard=g.OfficeCallbackGuard(native)
            self.assertEqual(guard(request).status_code,200);self.assertEqual(guard(request).status_code,200);self.assertEqual(len(calls),1)
            values.clear()
            def uncertain(r):calls.append(r);raise RuntimeError('uncertain native save')
            guard=g.OfficeCallbackGuard(uncertain)
            with self.assertRaises(RuntimeError):guard(request)
            self.assertEqual(guard(request).status_code,409);self.assertEqual(len(calls),2)
            request.headers={};self.assertEqual(guard(request).status_code,403);self.assertEqual(len(calls),2)
            request.method='GET';self.assertEqual(guard(request).status_code,405)
            request.path='/api2/ping/';self.assertEqual(g.OfficeCallbackGuard(lambda r:Response({'ok':True}))(request).status_code,200)

    def test_resigned_operation_has_same_replay_identity(self):
        body=json.dumps(PAYLOAD).encode()
        original=g.validate_callback(token(),body,SECRET,1100)[0]
        self.assertEqual(original,g.validate_callback(token(iat=1050,exp=1350),body,SECRET,1100)[0])
        self.assertNotEqual(original,g.validate_callback(token({**PAYLOAD,'status':2}),json.dumps({**PAYLOAD,'status':2}).encode(),SECRET,1100)[0])
        for url in ['https://office:8443/cache/files/%252e%252e/a','https://office:8443/cache/files/%5c../a','https://office:8443/cache/files/a\n','https://office:8443/cache/files/%00/a',None,3]:
            body={**PAYLOAD,'url':url}
            with self.subTest(url=url),self.assertRaises(ValueError):g.validate_callback(token(body),json.dumps(body).encode(),SECRET,1100)

    def test_missing_completion_and_legacy_ledger_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'ledger.sqlite3'
            conn=sqlite3.connect(path);conn.execute('CREATE TABLE callbacks(key TEXT PRIMARY KEY,expires INTEGER NOT NULL,state TEXT NOT NULL)');conn.commit();conn.close()
            ledger=g.CallbackLedger(path)
            with self.assertRaises(ValueError):ledger.complete('absent')
            conn=sqlite3.connect(path);conn.execute("INSERT INTO callbacks VALUES ('office-callback:old',1300,'pending')");conn.commit();conn.close()
            with self.assertRaises(ValueError):ledger.reserve('office-callback-v2:new',1400)
            conn=sqlite3.connect(path)
            self.assertEqual(conn.execute('SELECT state FROM callbacks').fetchall(),[('pending',)])
            conn.close()

    def test_uncertain_ledger_ack_and_boolean_native_success_are_not_acknowledged(self):
        class Ledger:
            def reserve(self,*args):return 'new'
            def complete(self,*args):raise OSError('disk full')
        class Response:
            def __init__(self,data,status=200):self.content=json.dumps(data).encode();self.status_code=status
        modules={'django.conf':types.SimpleNamespace(settings=types.SimpleNamespace(ONLYOFFICE_JWT_SECRET=SECRET)),'django.http':types.SimpleNamespace(JsonResponse=Response)}
        request=types.SimpleNamespace(path='/onlyoffice/editor-callback/',method='POST',headers={'Authorization':token()},body=json.dumps(PAYLOAD).encode())
        with patch.dict('sys.modules',modules),patch.object(g.time,'time',return_value=1100),patch.object(g,'CallbackLedger',Ledger):
            self.assertEqual(g.OfficeCallbackGuard(lambda r:Response({'error':0}))(request).status_code,503)
            self.assertEqual(g.OfficeCallbackGuard(lambda r:Response({'error':False}))(request).status_code,502)

    def test_durable_ledger_survives_reopen_and_refuses_missing_or_linked_state(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'ledger.sqlite3'
            with self.assertRaises(ValueError):g.CallbackLedger(path).reserve('key',1300)
            conn=sqlite3.connect(path);conn.execute('CREATE TABLE callbacks(key TEXT PRIMARY KEY,expires INTEGER NOT NULL,state TEXT NOT NULL)');conn.commit();conn.close()
            self.assertEqual(g.CallbackLedger(path).reserve('key',1300),'new')
            self.assertEqual(g.CallbackLedger(path).reserve('key',1300),'pending')
            g.CallbackLedger(path).complete('key')
            self.assertEqual(g.CallbackLedger(path).reserve('key',1300),'done')
            self.assertEqual(g.CallbackLedger(path).reserve('uncertain',1300),'new')
            self.assertEqual(g.CallbackLedger(path).reserve('uncertain',1300),'pending')
            link=Path(root)/'alias';link.symlink_to(path)
            with self.assertRaises(ValueError):g.CallbackLedger(link).reserve('key',1300)

if __name__=='__main__':unittest.main()
