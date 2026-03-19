import requests
import uuid
import json
import pickle
import hashlib
from pathlib import Path
from typing import Callable, Optional, List
from .exceptions import VhiAuthenticationError, VhiMfaRequiredError, VhiApiError
from .models import ClaimStatement


class VhiClient:
    """
    A client library for interacting with the Vhi API.
    Handles authentication, MFA callbacks, claims retrieval, and document downloads.
    """

    DEFAULT_CONFIG_URL = (
        "https://www.vhi.ie/myvhi/myclaimstatements"  # Usually embedded here
    )

    def __init__(
        self,
        username: str,
        password: str,
        mfa_callback: Optional[Callable[[], str]] = None,
        cache_session: bool = True,
    ):
        """
        Initialize the VhiClient.

        Args:
            username: User's email address.
            password: User's password.
            mfa_callback: A callable that returns the 2FA OTP string when invoked.
            cache_session: Whether to cache session cookies locally to prevent re-authentication.
        """
        self.username = username
        self.password = password
        self.mfa_callback = mfa_callback
        self.cache_session = cache_session

        # State management
        self.session = requests.Session()

        # Default Browser Headers to mimic browser and avoid WAF
        self.session.headers.update(
            {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
                "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            }
        )

        self.is_authenticated = False
        self.apis_base_url = (
            "https://apis.vhi.ie"  # Will be updated during discovery if necessary
        )

    def _get_cache_path(self) -> Path:
        user_hash = hashlib.md5(self.username.encode("utf-8")).hexdigest()
        cache_dir = Path.home() / ".vhi"
        cache_dir.mkdir(exist_ok=True)
        return cache_dir / f"session_{user_hash}.pkl"

    def _save_session(self):
        if not self.cache_session:
            return
        with open(self._get_cache_path(), "wb") as f:
            pickle.dump(self.session.cookies, f)

    def _load_session(self) -> bool:
        if not self.cache_session:
            return False
        cache_path = self._get_cache_path()
        if cache_path.exists():
            try:
                with open(cache_path, "rb") as f:
                    self.session.cookies = pickle.load(f)
                return True
            except Exception:
                pass
        return False

    def _is_session_valid(self) -> bool:
        try:
            url = f"{self.apis_base_url}/claims/v1/statements"
            headers = {
                "Accept": "application/json",
                "Origin": "https://app.vhi.ie",
                "Referer": "https://app.vhi.ie/",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-site",
            }
            # Only test to see if 401 is returned
            response = self.session.get(url, headers=headers, timeout=5)
            return response.status_code == 200
        except Exception:
            return False

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
        if self._load_session():
            if self._is_session_valid():
                self.is_authenticated = True
                return
            else:
                self.session.cookies.clear()

        # Set proper fetch headers mimicking trace exactly
        headers = {
            "accept": "application/json, text/plain, */*",
            "accept-language": "en-IE,en-US;q=0.9,en;q=0.8,ja;q=0.7,en-GB;q=0.6,de;q=0.5",
            "cache-control": "no-cache",
            "content-type": "application/json",
            "dnt": "1",
            "origin": "https://app.vhi.ie",
            "pragma": "no-cache",
            "priority": "u=1, i",
            "referer": "https://app.vhi.ie/",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-session-id": str(uuid.uuid4()),
        }

        payload = {"username": self.username, "usercred": self.password}

        # Format strictly without spaces to bypass strict WAF parsers
        raw_payload = json.dumps(payload, separators=(",", ":"))

        # 1. Primary Authentication
        login_url = f"{self.apis_base_url}/api/myvhilogin/login"

        response = self.session.post(login_url, data=raw_payload, headers=headers)

        if response.status_code == 200:
            try:
                data = response.json()
            except ValueError:
                raise VhiApiError(
                    "Login response was not valid JSON",
                    status_code=response.status_code,
                )

            # The HAR trace uses a deeply nested response structure or a flattened one depending on Gateway
            status_val = data.get("status") or data.get("data", {}).get("status")

            if status_val == "MFA_REQUIRED":
                state_token = data.get("stateToken") or data.get("data", {}).get(
                    "stateToken"
                )

                # Attempt to extract the verify url from the factors array
                try:
                    embedded_factors = (
                        data.get("data", {}).get("_embedded", {}).get("factors", [])
                    )
                    root_factors = data.get("factors", [])
                    factors = embedded_factors if embedded_factors else root_factors

                    try:
                        verify_url = factors[0]["_links"]["verify"]["href"]
                    except KeyError:
                        factor_id = factors[0]["id"]
                        verify_url = f"https://admin-digital.vhi.ie/api/v1/authn/factors/{factor_id}/verify"
                except (IndexError, KeyError) as e:
                    raise VhiApiError(
                        f"MFA required but could not parse the factor verification URL. {e}"
                    )

                if not state_token:
                    raise VhiApiError(
                        "MFA required but no state_token provided in response"
                    )

                self._handle_mfa_challenge(state_token, verify_url, headers)
            else:
                self.is_authenticated = True
                self._save_session()
                return

        elif response.status_code == 401:
            raise VhiAuthenticationError("Invalid credentials provided.")
        else:
            raise VhiApiError(
                f"Login failed with status {response.status_code}: {response.text}",
                status_code=response.status_code,
                response=response,
            )

    def _handle_mfa_challenge(
        self, state_token: str, verify_url: str, base_headers: dict
    ):
        """
        Internal method to submit the MFA code.
        """
        if not self.mfa_callback:
            raise VhiMfaRequiredError(
                "MFA is required but no mfa_callback was provided to VhiClient."
            )

        # 1. Trigger the SMS / challenge
        trigger_payload = {"stateToken": state_token}
        trigger_raw_payload = json.dumps(trigger_payload, separators=(",", ":"))
        trigger_response = self.session.post(
            verify_url, data=trigger_raw_payload, headers=base_headers
        )

        if trigger_response.status_code != 200:
            raise VhiApiError(
                f"Failed to trigger MFA challenge. Status: {trigger_response.status_code} - {trigger_response.text}"
            )

        # Pause execution and invoke the user-defined callback to get the OTP
        otp_code = self.mfa_callback()

        if not otp_code:
            raise VhiAuthenticationError(
                "MFA callback did not return a valid OTP code."
            )

        payload = {"passCode": otp_code, "stateToken": state_token}

        raw_payload = json.dumps(payload, separators=(",", ":"))
        response = self.session.post(verify_url, data=raw_payload, headers=base_headers)

        if response.status_code == 200:
            self.is_authenticated = True
            self._save_session()
            # The session cookie jar has now been populated with the authorized session
            # Or we might need to extract a Bearer token. This implementation relies
            # on cookies being correctly set via Set-Cookie headers by the API.
        else:
            raise VhiAuthenticationError(
                f"MFA verification failed. Status: {response.status_code} - {response.text}"
            )

    def get_claims(self) -> List[ClaimStatement]:
        """
        Retrieves the list of claim statements.

        Returns:
            List of ClaimStatement objects.
        """
        if not self.is_authenticated:
            raise VhiAuthenticationError(
                "Client is not authenticated. Call login() first."
            )

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
                raise VhiApiError(
                    "Invalid JSON received for claims statements.",
                    status_code=response.status_code,
                )

            claims_data = data.get("claims", [])
            return [ClaimStatement.from_dict(claim) for claim in claims_data]
        elif response.status_code == 401:
            self.is_authenticated = False
            raise VhiAuthenticationError("Session expired or unauthorized.")
        else:
            raise VhiApiError(
                f"Failed to fetch claims: {response.status_code}",
                status_code=response.status_code,
                response=response,
            )

    def download_document(self, document_id: str, dest_path: str):
        """
        Streams a claim PDF document to the local disk.

        Args:
            document_id: The ID of the document to download.
            dest_path: The file path where the PDF should be saved.
        """
        if not self.is_authenticated:
            raise VhiAuthenticationError(
                "Client is not authenticated. Call login() first."
            )

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
                with open(dest_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
            elif response.status_code == 401:
                self.is_authenticated = False
                raise VhiAuthenticationError(
                    "Session expired or unauthorized while downloading document."
                )
            else:
                raise VhiApiError(
                    f"Failed to download document {document_id}: {response.status_code}",
                    status_code=response.status_code,
                    response=response,
                )
