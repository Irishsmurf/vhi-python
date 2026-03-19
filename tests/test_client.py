import pytest
import responses
import os
import tempfile
from vhi.client import VhiClient
from vhi.exceptions import VhiAuthenticationError, VhiMfaRequiredError, VhiApiError

@responses.activate
def test_login_success_no_mfa():
    client = VhiClient("test@example.com", "password")
    
    responses.add(
        responses.POST,
        "https://apis.vhi.ie/api/myvhilogin/login",
        json={"status": "SUCCESS", "sessionToken": "test-token"},
        status=200
    )
    
    client.login()
    assert client.is_authenticated is True

@responses.activate
def test_login_requires_mfa_success():
    def mfa_callback():
        return "123456"
        
    client = VhiClient("test@example.com", "password", mfa_callback=mfa_callback)
    
    # Mock primary login returning 200 with MFA_REQUIRED
    responses.add(
        responses.POST,
        "https://apis.vhi.ie/api/myvhilogin/login",
        json={
            "status": "MFA_REQUIRED", 
            "stateToken": "state-123",
            "factors": [{"_links": {"verify": {"href": "https://admin-digital.vhi.ie/api/v1/authn/factors/verify"}}}]
        },
        status=200
    )
    
    # Mock MFA verify returning 200 SUCCESS
    responses.add(
        responses.POST,
        "https://admin-digital.vhi.ie/api/v1/authn/factors/verify",
        json={"status": "SUCCESS", "sessionToken": "final-token"},
        status=200
    )
    
    client.login()
    assert client.is_authenticated is True

@responses.activate
def test_login_invalid_credentials():
    client = VhiClient("test@example.com", "wrong")
    
    responses.add(
        responses.POST,
        "https://apis.vhi.ie/api/myvhilogin/login",
        status=401
    )
    
    with pytest.raises(VhiAuthenticationError):
        client.login()

@responses.activate
def test_get_claims_success():
    client = VhiClient("test@example.com", "password")
    client.is_authenticated = True # Mock existing session
    
    responses.add(
        responses.GET,
        "https://apis.vhi.ie/claims/v1/statements",
        json={
            "claims": [
                {
                    "claimId": "CLM-123",
                    "dateOfService": "2026-03-15",
                    "practitioner": "Dr. Smith",
                    "documentId": "DOC-123",
                    "status": "Processed"
                }
            ]
        },
        status=200
    )
    
    claims = client.get_claims()
    assert len(claims) == 1
    assert claims[0].claim_id == "CLM-123"
    assert claims[0].practitioner == "Dr. Smith"

@responses.activate
def test_download_document_success():
    client = VhiClient("test@example.com", "password")
    client.is_authenticated = True
    
    pdf_content = b"%PDF-1.4 mock pdf content"
    
    responses.add(
        responses.GET,
        "https://apis.vhi.ie/documents/v1/DOC-123/download",
        body=pdf_content,
        status=200,
        content_type="application/pdf"
    )
    
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        dest_path = tmp.name
        
    try:
        client.download_document("DOC-123", dest_path)
        with open(dest_path, "rb") as f:
            saved_content = f.read()
            assert saved_content == pdf_content
    finally:
        os.remove(dest_path)
