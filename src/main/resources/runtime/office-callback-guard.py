"""Authenticate and constrain the native Seafile ONLYOFFICE callback before it can fetch/write."""
if not __debug__:
    raise SystemExit('Optimized Office callback guard refused before imports or effects')
import base64
import hashlib
import hmac
import json
import re
import sqlite3
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit


def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate JSON field')
        result[key]=value
    return result


def validate_callback(header,body,secret,now):
    if len(body)>1048576 or not isinstance(secret,str) or len(secret)<32:raise ValueError('Invalid callback envelope')
    payload=json.loads(body,object_pairs_hook=unique_object)
    if not isinstance(payload,dict):raise ValueError('Invalid callback body')
    # CE 10 adds a purpose-bound body token even with outbox.inBody=false.
    # Prefer that native envelope; never treat an editor configuration JWT as a callback.
    token=payload.get('token')
    if token is None:
        if not header.startswith('Bearer '):raise ValueError('Missing callback authentication')
        token=header[7:]
    if not isinstance(token,str) or len(token)>150000:raise ValueError('Invalid callback authentication')
    parts=token.split('.')
    if len(parts)!=3 or any(not re.fullmatch('[A-Za-z0-9_-]+',part) for part in parts):raise ValueError('Invalid token encoding')
    def decode(value):
        decoded=base64.urlsafe_b64decode(value+'='*((-len(value))%4))
        if base64.urlsafe_b64encode(decoded).decode().rstrip('=')!=value:raise ValueError('Noncanonical token encoding')
        return decoded
    algorithm=json.loads(decode(parts[0]),object_pairs_hook=unique_object)
    if not isinstance(algorithm,dict) or algorithm.get('alg')!='HS256' or set(algorithm)-{'alg','typ'}:raise ValueError('Unsupported signature')
    if not hmac.compare_digest(decode(parts[2]),hmac.new(secret.encode(),('.'.join(parts[:2])).encode(),hashlib.sha256).digest()):raise ValueError('Invalid signature')
    claims=json.loads(decode(parts[1]),object_pairs_hook=unique_object)
    if not isinstance(claims,dict):raise ValueError('Invalid token claims')
    expiry,issued=claims.get('exp'),claims.get('iat')
    if type(expiry) is not int or type(issued) is not int or issued>now+30 or expiry<=now or expiry-issued not in range(1,361):raise ValueError('Invalid token lifetime')
    if claims.get('operation')!='callback':raise ValueError('Wrong JWT purpose')
    canonical={key:value for key,value in payload.items() if key!='token'}
    signed=claims.get('payload') if 'payload' in claims else {key:value for key,value in claims.items() if key not in ('iat','exp','operation')}
    encode=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
    if encode(signed)!=encode(canonical):raise ValueError('Callback body not bound to signature')
    if type(payload.get('status')) is not int or payload['status'] not in (1,2,3,4,6,7):raise ValueError('Unsupported callback status')
    if not isinstance(payload.get('key'),str) or not re.fullmatch('[A-Za-z0-9_.=-]{1,128}',payload['key']):raise ValueError('Invalid document key')
    for field in ('url','changesurl'):
        if field in payload:
            value=payload[field]
            if not isinstance(value,str) or any(ord(c)<33 or ord(c)==127 for c in value) or '\\' in value:
                raise ValueError('Invalid callback download URL')
            url=urlsplit(value);decoded=unquote(url.path,errors='strict');segments=decoded.split('/')
            if (url.scheme!='https' or url.netloc!='office:8443' or url.fragment or
                not url.path.startswith('/cache/files/') or '%' in decoded or '\\' in decoded or
                any(ord(c)<32 or ord(c)==127 for c in decoded) or any(x in ('.','..') for x in segments)):
                raise ValueError('Unapproved callback download origin')
    if payload['status'] in (2,6) and 'url' not in payload:raise ValueError('Missing callback document')
    # JWTs may be reissued with different iat/exp or equivalent JSON formatting.
    # Replay authority is the authenticated operation, never the bearer serialization.
    return 'office-callback-v2:'+hashlib.sha256(encode(canonical).encode()).hexdigest(),max(1,int(expiry-now))


class CallbackLedger:
    def __init__(self,path='/state/office-callbacks.sqlite3'):self.path=Path(path)
    def connect(self):
        if self.path.is_symlink() or not self.path.is_file():raise ValueError('Callback ledger missing or foreign')
        conn=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,timeout=5)
        try:
            conn.execute('PRAGMA synchronous=FULL');conn.execute('PRAGMA trusted_schema=OFF')
            # Old token-keyed entries cannot be safely mapped to semantic operations.
            # Preserve them for explicit offline reconciliation, never bypass on upgrade.
            if conn.execute("SELECT 1 FROM callbacks WHERE key LIKE 'office-callback:%' LIMIT 1").fetchone():
                raise ValueError('Legacy callback ledger requires reconciliation')
            return conn
        except BaseException:
            conn.close()
            raise
    def observe_readonly(self,key):
        # This is the EXACT deployed guard's operation key and native SQLite file,
        # never an acceptance-supplied path, SQL statement or caller-declared state.
        if not isinstance(key,str) or not re.fullmatch('office-callback-v2:[a-f0-9]{64}',key):
            raise ValueError('Foreign Office callback operation')
        path=Path('/state/office-callbacks.sqlite3')
        if self.path!=path or path.is_symlink() or not path.is_file() or path.stat().st_size>134217728:
            raise ValueError('Foreign or unbounded native Office callback ledger')
        conn=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=3)
        try:
            conn.execute('PRAGMA query_only=ON');conn.execute('PRAGMA trusted_schema=OFF')
            if conn.execute("SELECT 1 FROM callbacks WHERE key LIKE 'office-callback:%' LIMIT 1").fetchone():
                raise ValueError('Legacy uncertain Office callbacks require reconciliation')
            completed=conn.execute("SELECT COUNT(*) FROM callbacks WHERE state='done' AND key LIKE 'office-callback-v2:%'").fetchone()[0]
            state=conn.execute('SELECT state FROM callbacks WHERE key=?',(key,)).fetchone()
            if type(completed) is not int or completed>100000 or state is not None and state[0] not in ('pending','done'):
                raise ValueError('Unbounded or foreign Office callback ledger state')
            return {'schemaVersion':1,'completedCount':completed,'operationKey':key,
                    'state':None if state is None else state[0],
                    'replayAdmission':'deny' if state is not None else 'new-only'}
        finally:conn.close()
    def reserve(self,key,expires):
        conn=self.connect()
        try:
            conn.execute('BEGIN IMMEDIATE')
            inserted=conn.execute("INSERT OR IGNORE INTO callbacks(key,expires,state) VALUES (?,?,'pending')",(key,expires)).rowcount
            state=conn.execute('SELECT state FROM callbacks WHERE key=?',(key,)).fetchone()[0]
            conn.commit()
            return 'new' if inserted else state
        finally:conn.close()
    def complete(self,key):
        conn=self.connect()
        try:
            changed=conn.execute("UPDATE callbacks SET state='done' WHERE key=? AND state='pending'",(key,)).rowcount
            if changed!=1:raise ValueError('Callback reservation missing or already completed')
            conn.commit()
        finally:conn.close()


class OfficeCallbackGuard:
    def __init__(self,get_response):self.get_response=get_response
    def __call__(self,request):
        if request.path!='/onlyoffice/editor-callback/':return self.get_response(request)
        from django.conf import settings
        from django.http import JsonResponse
        if request.method!='POST':return JsonResponse({'error':1},status=405)
        try:key,ttl=validate_callback(request.headers.get('Authorization',''),request.body,settings.ONLYOFFICE_JWT_SECRET,time.time())
        except (ValueError,TypeError,KeyError,UnicodeError):return JsonResponse({'error':1},status=403)
        try:
            ledger=CallbackLedger();state=ledger.reserve(key,int(time.time())+ttl)
            if state=='done':return JsonResponse({'error':0})
            if state!='new':return JsonResponse({'error':1},status=409)
        except Exception:return JsonResponse({'error':1},status=503)
        # Keep an uncertain result pending. Do not replay a potentially committed native save.
        response=self.get_response(request)
        try:
            result=json.loads(response.content,object_pairs_hook=unique_object)
            if response.status_code==200 and isinstance(result,dict) and set(result)=={'error'} and type(result['error']) is int and result['error']==0:
                ledger.complete(key)
            elif response.status_code==200:
                return JsonResponse({'error':1},status=502)
        except Exception:
            # A committed save without a durable acknowledgement remains uncertain.
            return JsonResponse({'error':1},status=503)
        return response


if __name__=='__main__':
    import sys
    try:
        if len(sys.argv)!=3 or sys.argv[1]!='--readonly-collector':
            raise ValueError('Foreign native Office collector invocation')
        result=CallbackLedger().observe_readonly(sys.argv[2])
        encoded=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
        if len(encoded)>4096:raise ValueError('Unbounded native callback collector result')
        print(encoded)
    except Exception:
        raise SystemExit('Original native Office callback collector refused; preserve pending intent') from None
