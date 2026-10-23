"""Bounded canonical HTTP witness transport with explicit host TLS configuration.

Only loopback test deployments may explicitly opt into cleartext. Remote use
requires a verifying SSLContext; signed replies remain mandatory at the publisher.
The server does not interpret arbitrary URLs, commands, paths or source code.
"""
import http.client
import ssl
import ipaddress
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit
from .evidence_encoding import canonical_bytes,loads
from .evidence_service import EvidenceError
from .evidence_witness import WitnessScope,WitnessRequest,WitnessAck,WitnessReack,Checkpoint
from .evidence_witness_store import MAX_WIRE,decode_ack,decode_head,ack_document
from .signing import Signature

def encode_reply(reply):
    if type(reply) is WitnessAck:return ack_document(reply)
    if type(reply) is WitnessReack:return {'body':reply.body(),'signature':reply.signature}
    return reply

def decode_reply(doc):
    schema=doc['body']['schema']
    if schema=='regulated/witness-ack/v1':return decode_ack(doc)
    if schema=='regulated/witness-reack/v1':
        b=doc['body']
        if set(b)!={'schema','witness_id','request_id','ack'}:raise EvidenceError('reack fields')
        return WitnessReack(b['witness_id'],b['request_id'],decode_ack(b['ack']),Signature(**doc['signature']))
    if schema!='regulated/witness-refusal/v1':raise EvidenceError('witness reply schema')
    return doc

def decode_request(doc,policies):
    if type(doc) is not dict or set(doc)!={'schema','request_id','scope_type','scope_id','namespace','previous','checkpoint','consistency'}:raise EvidenceError('request fields')
    scope=WitnessScope(doc['scope_type'],doc['scope_id'],doc['namespace']);policy=policies[scope]
    if doc['schema']!='regulated/witness-request/v1':raise EvidenceError('request schema')
    old=None if doc['previous'] is None else Checkpoint(**doc['previous'])
    request=WitnessRequest(doc['request_id'],scope,old,decode_head(doc['checkpoint']['head']),tuple(bytes.fromhex(h) for h in doc['consistency']))
    if canonical_bytes(request.document(policy))!=canonical_bytes(doc):raise EvidenceError('request canonical binding')
    return request

class WitnessHTTPClient:
    def __init__(self,url,*,policies,timeout=2.0,tls_context=None,allow_loopback_http=False):
        u=urlsplit(url)
        if u.username or u.password or u.query or u.fragment or u.path not in ('','/') or not u.hostname or not 0<timeout<=30:raise EvidenceError('witness endpoint configuration')
        if u.scheme=='https':
            if not isinstance(tls_context,ssl.SSLContext) or tls_context.verify_mode!=ssl.CERT_REQUIRED or not tls_context.check_hostname:raise EvidenceError('verifying witness TLS context required')
        elif u.scheme=='http':
            try:loopback=ipaddress.ip_address(u.hostname).is_loopback
            except ValueError:loopback=False
            if not allow_loopback_http or not loopback:raise EvidenceError('cleartext witness requires explicit loopback fixture')
        else:raise EvidenceError('unsupported witness transport')
        self.url=u;self.timeout=timeout;self.tls=tls_context;self.policies=dict(policies)
    def _call(self,operation,body):
        raw=canonical_bytes(body)
        if len(raw)>MAX_WIRE:raise EvidenceError('witness request bytes')
        if self.url.scheme=='https':c=http.client.HTTPSConnection(self.url.hostname,self.url.port or 443,timeout=self.timeout,context=self.tls)
        else:c=http.client.HTTPConnection(self.url.hostname,self.url.port or 80,timeout=self.timeout)
        try:
            c.request('POST','/'+operation,raw,{'Content-Type':'application/json','Content-Length':str(len(raw))})
            response=c.getresponse()
            if response.status!=200:raise EvidenceError('witness transport refused request')
            length=response.getheader('Content-Length')
            if length is None or not length.isdecimal() or int(length)>MAX_WIRE:raise EvidenceError('witness response length')
            data=response.read(int(length)+1)
            if len(data)!=int(length):raise EvidenceError('truncated witness response')
            doc=loads(data)
            if canonical_bytes(doc)!=data:raise EvidenceError('noncanonical witness response')
            return doc
        finally:c.close()
    def latest(self,scope,nonce):return self._call('latest',{'scope':scope.fields(),'nonce':nonce})
    def ack_range(self,scope,after_digest,*,limit=64):
        doc=self._call('ack-range',{'scope':scope.fields(),'after':after_digest,'limit':limit})
        if type(doc) is not list or len(doc)>64:raise EvidenceError('ack range shape')
        return tuple(decode_ack(item) for item in doc)
    def request(self,request):return decode_reply(self._call('request',request.document(self.policies[request.scope])))
    def batch(self,requests):
        if type(requests) is not tuple or not 1<=len(requests)<=64:raise EvidenceError('batch bound')
        doc=self._call('batch',{'items':[r.document(self.policies[r.scope]) for r in requests]})
        if type(doc) is not list or len(doc)!=len(requests):raise EvidenceError('batch response shape')
        return tuple(decode_reply(item) for item in doc)

class WitnessHTTPServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,endpoint,*,tls_context=None,allow_loopback_http=False,max_connections=16):
        if type(max_connections) is not int or not 1<=max_connections<=64:raise EvidenceError('connection bound')
        if tls_context is None:
            try:local=ipaddress.ip_address(address[0]).is_loopback
            except ValueError:local=False
            if not allow_loopback_http or not local:raise EvidenceError('server TLS required')
        if tls_context is not None and not isinstance(tls_context,ssl.SSLContext):raise EvidenceError('server TLS context required')
        self.endpoint=endpoint;self.slots=threading.BoundedSemaphore(max_connections);self.tls=tls_context
        super().__init__(address,_Handler)
    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
        try:super().process_request(request,client_address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,client_address):
        try:
            # TLS handshakes run in a bounded worker, never in the accept loop.
            # A stalled peer cannot stop other configured connection slots.
            if self.tls is not None:
                request.settimeout(5)
                request=self.tls.wrap_socket(request,server_side=True,do_handshake_on_connect=False)
                request.do_handshake()
            super().process_request_thread(request,client_address)
        except OSError:self.shutdown_request(request)
        finally:self.slots.release()

class _Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    def setup(self):
        super().setup();self.connection.settimeout(5)
    def log_message(self,*args):pass
    def do_POST(self):
        try:
            lengths=self.headers.get_all('Content-Length') or []
            if len(lengths)!=1 or not lengths[0].isdecimal() or not 0<int(lengths[0])<=MAX_WIRE or self.headers.get('Transfer-Encoding'):raise EvidenceError('request length')
            raw=self.rfile.read(int(lengths[0]));doc=loads(raw)
            if len(raw)!=int(lengths[0]) or canonical_bytes(doc)!=raw:raise EvidenceError('request encoding')
            endpoint=self.server.endpoint
            if self.path=='/request':reply=encode_reply(endpoint.request(decode_request(doc,endpoint.policies)))
            elif self.path=='/batch':
                if set(doc)!={'items'} or type(doc['items']) is not list or not 1<=len(doc['items'])<=64:raise EvidenceError('batch shape')
                reply=[encode_reply(r) for r in endpoint.batch(tuple(decode_request(d,endpoint.policies) for d in doc['items']))]
            elif self.path=='/latest':
                if set(doc)!={'scope','nonce'}:raise EvidenceError('latest fields')
                reply=endpoint.latest(WitnessScope(**doc['scope']),doc['nonce'])
            elif self.path=='/ack-range':
                if set(doc)!={'scope','after','limit'}:raise EvidenceError('range fields')
                reply=[ack_document(a) for a in endpoint.ack_range(WitnessScope(**doc['scope']),doc['after'],limit=doc['limit'])]
            else:raise EvidenceError('unknown witness operation')
            payload=canonical_bytes(reply)
            if len(payload)>MAX_WIRE:raise EvidenceError('response bound')
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
        except (KeyError,TypeError,ValueError,OSError) as exc:
            self.send_error(400,'Witness request refused')
