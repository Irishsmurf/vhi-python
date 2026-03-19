import os
import pytest
from vhi.client import VhiClient
from vhi.exceptions import VhiMfaRequiredError, VhiAuthenticationError

@pytest.mark.skipif(
    not os.getenv("VHI_USERNAME") or not os.getenv("VHI_PASSWORD"),
    reason="Integration tests require VHI_USERNAME and VHI_PASSWORD environment variables"
)
def test_live_login():
    """
    Test live login against Vhi API.
    We expect to hit either a successful login or an MFA challenge.
    """
    username = os.environ["VHI_USERNAME"]
    password = os.environ["VHI_PASSWORD"]
    
    # We initialize without an mfa_callback to ensure it raises VhiMfaRequiredError
    # if MFA is prompted, which validates the primary credentials were correct.
    client = VhiClient(username, password)
    
    try:
        client.login()
        # If it succeeds without MFA, we are authenticated.
        assert client.is_authenticated is True
    except VhiMfaRequiredError:
        # If it throws MFA required, the API accepted the usercred and triggered Okta MFA.
        # This confirms our primary login endpoint and payload reverse-engineering is correct.
        pass
    except VhiAuthenticationError as e:
         pytest.fail(f"Integration login failed - incorrect credentials: {e}")
