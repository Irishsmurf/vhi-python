import requests
import os
from typing import Callable, Optional, List
from .exceptions import VhiAuthenticationError, VhiMfaRequiredError, VhiApiError
from .models import ClaimStatement

class VhiClient:
    """
    A client library for interacting with the Vhi API.
    Handles authentication, MFA callbacks, claims retrieval, and document downloads.
    """
    DEFAULT_CONFIG_URL = "https://www.vhi.ie/myvhi/myclaimstatements" # Usually embedded here
    
    def __init__(self, username: str, password: str, mfa_callback: Optional[Callable[[], str]] = None):
        """
        Initialize the VhiClient.
        
        Args:
            username: User's email address.
            password: User's password.
            mfa_callback: A callable that returns the 2FA OTP string when invoked.
        """
        self.username = username
        self.password = password
        self.mfa_callback = mfa_callback
        
        # State management
        self.session = requests.Session()
        
        # Default Browser Headers to mimic browser and avoid WAF
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        })
        
        self.is_authenticated = False
        self.apis_base_url = "https://apis.vhi.ie" # Will be updated during discovery if necessary
        
    def _fetch_environment_config(self):
        """
        Optional: Dynamically discovers the API base URL.
        Currently defaults to known https://apis.vhi.ie.
        """
        try:
            # We skip full parsing of the config to avoid complex scraping
            # We hardcode the reliable apis.vhi.ie gateway for now as per instructions.
            pass
        except Exception:
            pass

    def login(self):
        """
        Performs the login flow. Handles the MFA challenge if required.
        """
        # Set proper fetch headers
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": "https://www.vhi.ie",
            "Referer": "https://www.vhi.ie/",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
        }
        
        payload = {
            "username": self.username,
            "password": self.password
        }
        
        # 1. Primary Authentication
        # The path here is a presumed standard, will likely be updated if the actual path varies
        login_url = f"{self.apis_base_url}/auth/v1/login"
        
        response = self.session.post(login_url, json=payload, headers=headers)
        
        if response.status_code == 200:
            self.is_authenticated = True
            return
            
        elif response.status_code == 202:
            # MFA Challenge Required
            try:
                data = response.json()
            except ValueError:
                raise VhiApiError("MFA response was not valid JSON", status_code=response.status_code)
                
            if data.get("mfa_required"):
                state_token = data.get("state_token")
                if not state_token:
                    raise VhiApiError("MFA required but no state_token provided in response")
                    
                self._handle_mfa_challenge(state_token, headers)
            else:
                raise VhiApiError("Received 202 but not MFA challenge", status_code=response.status_code, response=response)
                
        elif response.status_code == 401:
            raise VhiAuthenticationError("Invalid credentials provided.")
        else:
            raise VhiApiError(f"Login failed with status {response.status_code}", status_code=response.status_code, response=response)
            
    def _handle_mfa_challenge(self, state_token: str, base_headers: dict):
        """
        Internal method to submit the MFA code.
        """
        if not self.mfa_callback:
            raise VhiMfaRequiredError("MFA is required but no mfa_callback was provided to VhiClient.")
            
        # Pause execution and invoke the user-defined callback to get the OTP
        otp_code = self.mfa_callback()
        
        if not otp_code:
            raise VhiAuthenticationError("MFA callback did not return a valid OTP code.")
            
        mfa_url = f"{self.apis_base_url}/auth/v1/mfa/verify"
        payload = {
            "otp": otp_code,
            "state_token": state_token
        }
        
        response = self.session.post(mfa_url, json=payload, headers=base_headers)
        
        if response.status_code == 200:
            self.is_authenticated = True
            
            # The session cookie jar has now been populated with the authorized session
            # Or we might need to extract a Bearer token. This implementation relies
            # on cookies being correctly set via Set-Cookie headers by the API.
        else:
            raise VhiAuthenticationError(f"MFA verification failed. Status: {response.status_code}")

    def get_claims(self) -> List[ClaimStatement]:
        """
        Retrieves the list of claim statements.
        
        Returns:
            List of ClaimStatement objects.
        """
        if not self.is_authenticated:
            raise VhiAuthenticationError("Client is not authenticated. Call login() first.")
            
        url = f"{self.apis_base_url}/claims/v1/statements"
        
        headers = {
            "Accept": "application/json",
            "Origin": "https://www.vhi.ie",
            "Referer": "https://www.vhi.ie/",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
        }
        
        response = self.session.get(url, headers=headers)
        
        if response.status_code == 200:
            try:
                data = response.json()
            except ValueError:
                raise VhiApiError("Invalid JSON received for claims statements.", status_code=response.status_code)
                
            claims_data = data.get("claims", [])
            return [ClaimStatement.from_dict(claim) for claim in claims_data]
        elif response.status_code == 401:
            self.is_authenticated = False
            raise VhiAuthenticationError("Session expired or unauthorized.")
        else:
            raise VhiApiError(f"Failed to fetch claims: {response.status_code}", status_code=response.status_code, response=response)
            
    def download_document(self, document_id: str, dest_path: str):
        """
        Streams a claim PDF document to the local disk.
        
        Args:
            document_id: The ID of the document to download.
            dest_path: The file path where the PDF should be saved.
        """
        if not self.is_authenticated:
            raise VhiAuthenticationError("Client is not authenticated. Call login() first.")
            
        url = f"{self.apis_base_url}/documents/v1/{document_id}/download"
        
        headers = {
            "Accept": "application/pdf",
            "Origin": "https://www.vhi.ie",
            "Referer": "https://www.vhi.ie/",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
        }
        
        # Use stream=True to prevent loading large PDFs into memory
        with self.session.get(url, headers=headers, stream=True) as response:
            if response.status_code == 200:
                with open(dest_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
            elif response.status_code == 401:
                self.is_authenticated = False
                raise VhiAuthenticationError("Session expired or unauthorized while downloading document.")
            else:
                raise VhiApiError(f"Failed to download document {document_id}: {response.status_code}", status_code=response.status_code, response=response)
