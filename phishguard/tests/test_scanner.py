import os
import pytest
from app.scanner import URLValidationError, analyze_trust_gap, parse_url, run_scan
from app import database

def test_valid_parse_registered_domain():
    p=parse_url('https://login.example.co.uk/path')
    assert p['registered_domain']=='example.co.uk'
    assert p['host']=='login.example.co.uk'

def test_invalid_url_rejected():
    with pytest.raises(URLValidationError): parse_url('ht^tp://bad url')
    with pytest.raises(URLValidationError): parse_url('')

def test_misleading_subdomain_domain_extraction():
    p=parse_url('https://google.com.account-verification.example.org/login')
    assert p['registered_domain']=='example.org'
    assert len(p['subdomains']) >= 2

def test_brand_in_path_does_not_create_phishing_warning():
    r=run_scan('https://example.org/google/login')
    assert r['trust_gap']['brand'] is None
    assert not any(f['name']=='Brand-domain mismatch' for f in r['findings'])
    assert r['risk_score']==0

def test_brand_domain_mismatch_regression():
    r=run_scan('https://google.com.account-verification.example.org/login')
    t=r['trust_gap']
    assert t['brand']=='Google'
    assert t['registered_domain']=='example.org'
    assert t['expected_domain']=='google.com'
    assert t['mismatch'] is True
    assert r['risk_score'] >= 50

def test_configured_brand_domain_matches():
    p=parse_url('https://accounts.google.com/signin')
    t=analyze_trust_gap(p)
    assert not t['mismatch']

def test_brand_name_in_path_segment_is_informational_only():
    r=run_scan('https://example.org/account-google-verify')
    assert r['trust_gap']['brand'] is None
    assert r['trust_gap']['brand_mentioned']=='Google'
    assert r['trust_gap']['mismatch'] is False
    assert r['risk_score']==0

def test_https_or_tld_alone_is_not_flagged():
    r=run_scan('https://example.com/')
    assert r['risk_score']==0
    assert r['risk_category']=='Lower Risk'

def test_risk_boundaries_are_consistent():
    assert run_scan('https://example.com').get('risk_score',0) < 25
    assert run_scan('http://example.com').get('risk_score',0) < 25

def test_no_model_and_no_reputation_are_reported_honestly():
    r=run_scan('https://example.com')
    assert r['model_status']['available'] is False
    assert r['reputation_status']['checked'] is False
    assert 'configured' in r['reputation_status']['detail'].lower()

def test_localhost_and_private_ip_never_fetch():
    local=run_scan('http://localhost/admin')
    private=run_scan('http://192.168.1.10/login')
    assert local['registered_domain']=='localhost'
    assert private['registered_domain']=='192.168.1.10'
    assert local['reputation_status']['checked'] is False
    assert private['reputation_status']['checked'] is False
    assert any(f['name']=='IP address used as hostname' for f in private['findings'])

def test_scan_history_create_and_delete(tmp_path,monkeypatch):
    monkeypatch.setattr(database,'DB_PATH',str(tmp_path/'test.sqlite3'))
    database.init_db()
    report=run_scan('https://example.com')
    sid=database.save_scan(report)
    assert database.get_scan(sid)['registered_domain']=='example.com'
    assert database.delete_scan(sid)
    assert database.get_scan(sid) is None

def test_clear_history(tmp_path,monkeypatch):
    monkeypatch.setattr(database,'DB_PATH',str(tmp_path/'test.sqlite3'))
    database.init_db(); database.save_scan(run_scan('https://example.com'))
    assert database.clear_scans()==1
    assert database.summary()['total_scanned']==0
