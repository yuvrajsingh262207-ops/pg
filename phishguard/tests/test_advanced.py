import pytest
import io, json, zipfile
from fastapi.testclient import TestClient
from app import database
from app.scanner import URLValidationError, parse_url, run_scan
from app.counterfactual import compare
from app.dna import build_graph, synthetic_demo_graph
from app.main import app


def test_punycode_hostname_is_detected_and_decoded():
    parsed = parse_url('https://xn--pple-43d.com/login')
    assert parsed['registered_domain'] == 'xn--pple-43d.com'
    assert parsed['ascii_host'] == 'xn--pple-43d.com'
    assert parsed['unicode_host'] == 'аpple.com'  # Cyrillic small a; visibly different from Latin apple.com
    assert parsed['has_punycode'] is True
    assert any(f['name'] == 'Internationalized hostname' for f in run_scan('https://xn--pple-43d.com/login')['findings'])


def test_https_alone_and_brand_mention_are_not_verdicts():
    assert run_scan('https://example.org/google/login')['risk_score'] == 0
    assert run_scan('https://example.org/google/login')['trust_gap']['mismatch'] is False


def test_no_fetch_and_no_external_check():
    report = run_scan('https://example.org')
    assert all(x['status'] != 'completed' for x in report['stages'] if x['name'] in {'Threat intelligence','Infrastructure intelligence'})
    assert report['reputation_status']['status'] == 'not_configured'


def test_counterfactual_runs_same_pipeline_and_does_not_force_output():
    result = compare('https://example.com/a', 'https://example.net/b')
    assert result['original']['detector_version'] == result['variant']['detector_version']
    assert result['original']['risk_score'] == result['variant']['risk_score']
    assert result['identical_risk_score'] is True
    assert result['model_comparison']['available'] is False


def test_counterfactual_detects_real_rule_change():
    result = compare('https://example.org/', 'https://google.com.account-verification.example.org/login')
    assert result['variant']['risk_score'] > result['original']['risk_score']
    assert any(x['name'] == 'Brand-domain mismatch' for x in result['changed_rules'])


def test_shared_registered_domain_is_direct_evidence_not_attribution():
    reports = [run_scan('https://login.example.org/a'), run_scan('https://accounts.example.org/b')]
    graph = build_graph(reports)
    edge = next(e for e in graph['edges'] if e['type'] == 'same-registered-domain')
    assert edge['classification'] == 'direct observation'
    assert 'does not prove a shared attacker' in edge['limitation']


def test_synthetic_dna_graph_labeled_and_no_fake_infrastructure():
    g = synthetic_demo_graph()
    assert g['synthetic'] is True
    assert 'Synthetic' in g['label']
    assert not any(n['type'] == 'ip' for n in g['nodes'])
    assert not any('IP' in e['evidence'] and 'not supplied' not in e['evidence'] for e in g['edges'])


def test_api_vertical_scan_batch_counterfactual_and_evaluation(tmp_path, monkeypatch):
    monkeypatch.setattr(database, 'DB_PATH', str(tmp_path / 'api.sqlite3'))
    database.init_db()
    with TestClient(app) as client:
        health = client.get('/api/health')
        assert health.status_code == 200 and health.json()['model'] == 'not_configured'
        bad = client.post('/api/scan', json={'url': 'javascript:alert(1)'})
        assert bad.status_code == 422
        scan = client.post('/api/scan', json={'url': 'https://google.com.account-verification.example.org/login'})
        assert scan.status_code == 200
        report = scan.json()
        assert report['registered_domain'] == 'example.org'
        assert report['id'] and report['stages']
        assert client.get(f"/api/scans/{report['id']}").json()['risk_score'] == report['risk_score']
        batch = client.post('/api/batch', json={'urls': ['https://a.example.org', 'not a URL']})
        assert batch.status_code == 200
        assert batch.json()['successful'] == 1 and batch.json()['failed'] == 1
        cf = client.post('/api/counterfactual', json={'original':'https://example.org','variant':'https://example.net'})
        assert cf.status_code == 200 and cf.json()['identical_risk_score']
        copilot = client.post('/api/copilot', json={'scan_id':report['id'],'question':'Which registered domain?'})
        assert copilot.status_code == 200 and 'example.org' in copilot.json()['answer']
        exported = client.get(f"/api/scans/{report['id']}/export")
        assert exported.status_code == 200 and exported.headers['content-type'].startswith('application/json')
        assert client.get('/api/evaluation').json()['status'] == 'Not evaluated'
        assert client.delete(f"/api/scans/{report['id']}").status_code == 200


def test_extension_check_is_ephemeral_and_package_is_valid(tmp_path, monkeypatch):
    monkeypatch.setattr(database, 'DB_PATH', str(tmp_path / 'extension.sqlite3'))
    database.init_db()
    with TestClient(app) as client:
        before = database.summary()['total_scanned']
        result = client.post('/api/extension/check', json={'url':'https://google.com.account-verification.example.org/login'})
        assert result.status_code == 200
        assert result.json()['persisted'] is False
        assert result.json()['risk_category'] == 'High Risk'
        assert database.summary()['total_scanned'] == before
        private_shape = client.post('/api/extension/check', json={
            'url':'https://example.org/login', 'userinfo_present':True,
            'query_present':True, 'query_length':64, 'fragment_present':True,
        })
        assert private_shape.status_code == 200
        assert private_shape.json()['url_features']['userinfo_present'] is True
        assert private_shape.json()['url_features']['query_length'] == 64
        assert 'user information' in private_shape.json()['findings'][0]['name'].lower()
        cors = client.options('/api/extension/check', headers={
            'Origin':'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'Access-Control-Request-Method':'POST',
            'Access-Control-Request-Headers':'content-type',
        })
        assert cors.status_code == 200
        assert cors.headers['access-control-allow-origin'].startswith('chrome-extension://')
        package = client.get('/api/extension/package')
        assert package.status_code == 200
        with zipfile.ZipFile(io.BytesIO(package.content)) as z:
            assert 'phishguard-sentinel/manifest.json' in z.namelist()
            assert json.loads(z.read('phishguard-sentinel/manifest.json'))['manifest_version'] == 3
            assert 'phishguard-sentinel/local-detector.js' in z.namelist()
            assert 'phishguard-sentinel/public_suffix_list.dat' in z.namelist()


def test_unsupported_protocol_rejected():
    with pytest.raises(URLValidationError):
        run_scan('ftp://example.org/file')
