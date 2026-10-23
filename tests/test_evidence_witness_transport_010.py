import threading
import pytest
from regulated_core.evidence_witness_transport import WitnessHTTPServer,WitnessHTTPClient
from regulated_core.evidence_witness import WitnessRequest,WitnessAck,WitnessReack
from regulated_core.evidence_service import EvidenceError
from test_evidence_publication_010 import runtime,case,retain

@pytest.fixture
def transport(runtime):
    pub,w,*_=runtime
    server=WitnessHTTPServer(('127.0.0.1',0),w,allow_loopback_http=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    client=WitnessHTTPClient('http://127.0.0.1:'+str(server.server_port),policies=w.policies,allow_loopback_http=True)
    try:yield client
    finally:server.shutdown();server.server_close();thread.join();pub.close()

def test_durable_request_reack_latest_and_range_over_socket(runtime,transport):
    pub,w,_,tree,heads,*_=runtime
    req=WitnessRequest('a'*32,pub.policy.scope,None,heads[-1],tree.consistency(0,3))
    assert type(transport.request(req)) is WitnessAck
    assert type(transport.request(req)) is WitnessReack
    assert len(transport.ack_range(pub.policy.scope,'0'*64))==1
    assert transport.latest(pub.policy.scope,'b'*32)['body']['nonce']=='b'*32

def test_real_publisher_uses_signed_network_responses(runtime,transport):
    pub=runtime[0];pub.endpoints={'w':transport}
    for i in range(3):retain(runtime,i)
    assert pub.publish(runtime[4][-1])==runtime[4][-1]

@pytest.mark.parametrize('url',['http://192.0.2.1','http://localhost','ftp://127.0.0.1','https://example.invalid','http://127.0.0.1/other'])
def test_transport_configuration_refuses_unsafe_or_ambiguous_endpoints(url):
    with pytest.raises(EvidenceError):WitnessHTTPClient(url,policies={},allow_loopback_http=True)

def test_duplicate_batch_rejected_and_no_acceptance(runtime,transport):
    pub,w,_,tree,heads,*_=runtime
    r=WitnessRequest('a'*32,pub.policy.scope,None,heads[-1],tree.consistency(0,3))
    with pytest.raises(EvidenceError):transport.batch((r,r))
    assert not w.ack_range(pub.policy.scope,'0'*64)


def test_stalled_tls_handshake_does_not_block_other_witness_requests(runtime,tmp_path):
    import ssl,socket,ipaddress,time
    from datetime import datetime,timedelta,timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME,'isolated-witness')])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).sign(key,hashes.SHA256()))
    cert_path=tmp_path/'tls-cert.pem';key_path=tmp_path/'tls-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM));key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server_context.load_cert_chain(cert_path,key_path)
    client_context=ssl.create_default_context(cafile=str(cert_path))
    pub,w,*_=runtime;server=WitnessHTTPServer(('127.0.0.1',0),w,tls_context=server_context,max_connections=2)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    stalled=socket.create_connection(('127.0.0.1',server.server_port),timeout=2)
    try:
        client=WitnessHTTPClient('https://127.0.0.1:'+str(server.server_port),policies=w.policies,timeout=2,tls_context=client_context)
        assert client.latest(pub.policy.scope,'d'*32)['body']['nonce']=='d'*32
    finally:
        stalled.close();server.shutdown();server.server_close();thread.join();pub.close()
