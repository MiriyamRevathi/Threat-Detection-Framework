import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_home_page(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'SentinelX' in response.data or b'Cyber Threat' in response.data or b'<!DOCTYPE html>' in response.data

def test_demo_route_valid(client):
    response = client.get('/demo/normal')
    assert response.status_code == 200
    assert b'Result' in response.data or b'threat_score' in response.data or b'<!DOCTYPE html>' in response.data

def test_demo_route_invalid(client):
    response = client.get('/demo/nonexistent')
    assert response.status_code == 404

def test_upload_route_get(client):
    response = client.get('/upload')
    assert response.status_code in (200, 302, 405)

def test_health_route(client):
    response = client.get('/health')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["status"] == "healthy"
    assert json_data["version"] == "2.0.0"
