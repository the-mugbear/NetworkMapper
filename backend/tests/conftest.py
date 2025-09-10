import os
import tempfile
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.db import models

# Use in-memory SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session")
def test_engine():
    """Create test database engine."""
    models.Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def db_session(test_engine):
    """Create a fresh database session for each test."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    """Create test client with database dependency override."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(app) as test_client:
        yield test_client
    
    app.dependency_overrides.clear()


@pytest.fixture
def temp_file():
    """Create a temporary file for testing file uploads."""
    temp_fd, temp_path = tempfile.mkstemp()
    yield temp_path
    os.close(temp_fd)
    os.unlink(temp_path)


@pytest.fixture
def sample_nmap_xml():
    """Sample Nmap XML data for testing."""
    return '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX test.xml 192.168.1.1" start="1640995200" startstr="Sat Jan  1 00:00:00 2022" version="7.92" xmloutputversion="1.05">
    <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
    <verbose level="0"/>
    <debugging level="0"/>
    <host starttime="1640995200" endtime="1640995210">
        <status state="up" reason="syn-ack" reason_ttl="0"/>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <hostnames>
            <hostname name="router.local" type="PTR"/>
        </hostnames>
        <ports>
            <extraports state="closed" count="998">
                <extrareasons reason="resets" count="998"/>
            </extraports>
            <port protocol="tcp" portid="22">
                <state state="open" reason="syn-ack" reason_ttl="0"/>
                <service name="ssh" product="OpenSSH" version="7.4" extrainfo="protocol 2.0" method="probed" conf="10"/>
            </port>
            <port protocol="tcp" portid="80">
                <state state="open" reason="syn-ack" reason_ttl="0"/>
                <service name="http" product="nginx" version="1.14.0" method="probed" conf="10"/>
            </port>
        </ports>
        <times srtt="1000" rttvar="1000" to="100000"/>
    </host>
</nmaprun>'''


@pytest.fixture
def sample_gnmap_data():
    """Sample gnmap data for testing."""
    return '''Nmap 7.92 scan initiated Mon Jul 15 10:30:01 2024 as: nmap -oG test.gnmap -sV -T4 192.168.1.1-2
Ports scanned: TCP(1000) UDP(0) SCTP(0) PROTOCOLS(0)

Host: 192.168.1.1 (router.local)	Status: Up
Host: 192.168.1.1 (router.local)	Ports: 22/open/tcp//ssh/OpenSSH 7.6p1/, 80/open/tcp//http/nginx 1.14.0/
Host: 192.168.1.2 (server.local)	Status: Up
Host: 192.168.1.2 (server.local)	Ports: 443/open/tcp//https/Apache httpd 2.4.29/
Nmap done at Mon Jul 15 10:30:25 2024; 2 IP addresses (2 hosts up) scanned in 24.12 seconds'''


@pytest.fixture
def sample_masscan_xml():
    """Sample Masscan XML data for testing."""
    return '''<?xml version="1.0"?>
<nmaprun scanner="masscan" start="1640995200" version="1.0.5" xmloutputversion="1.03">
<scaninfo type="syn" protocol="tcp" numservices="2" services="80,443"/>
<host endtime="1640995210">
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack" reason_ttl="0"/>
        </port>
        <port protocol="tcp" portid="443">
            <state state="open" reason="syn-ack" reason_ttl="0"/>
        </port>
    </ports>
</host>
</nmaprun>'''


@pytest.fixture
def sample_eyewitness_json():
    """Sample EyeWitness JSON data for testing."""
    return '''{
    "version": "3.7.0",
    "results": [
        {
            "remote_system": "http://192.168.1.1:80",
            "protocol": "http",
            "hostname": "web.local",
            "ip": "192.168.1.1",
            "port": 80,
            "page_title": "Welcome to nginx!",
            "screenshot_path": "/opt/eyewitness/screenshots/192.168.1.1_80.png",
            "server_header": "nginx/1.14.0",
            "content_length": 612,
            "response_code": 200,
            "page_text": "Welcome to nginx! This is a test web server.",
            "category": "Uncategorized"
        },
        {
            "remote_system": "https://192.168.1.2:443",
            "protocol": "https",
            "hostname": "secure.local",
            "ip": "192.168.1.2",
            "port": 443,
            "page_title": "Secure Login",
            "screenshot_path": "/opt/eyewitness/screenshots/192.168.1.2_443.png",
            "server_header": "Apache/2.4.29",
            "content_length": 1024,
            "response_code": 200,
            "page_text": "Please enter your credentials to access the secure area.",
            "category": "Login"
        }
    ]
}'''