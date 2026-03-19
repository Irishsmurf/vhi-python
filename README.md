# Vhi Python Client

A Python client library for interacting dynamically with the Vhi API. Provides automated handling of Session state, Multi-Factor Authentication (MFA) callbacks, Claims Retrieval, and memory-efficient Document Downloads.

## Installation

You can install the library directly from source (or via pip once published):

```bash
pip install vhi-python
```

Alternatively, to install it locally for development:

```bash
git clone https://github.com/agent/vhi-python.git
cd vhi-python
pip install -e .
```

## Quick Start Example

This example demonstrates how to use the library to log in, handle an MFA callback (simulated via CLI input), retrieve claims, and download a claim PDF.

```python
import os
from vhi.client import VhiClient
from vhi.exceptions import VhiAuthenticationError, VhiApiError

def my_cli_mfa_callback() -> str:
    """
    A simple callback function that pauses execution
    and waits for the user to input the 2FA code sent to their phone/email.
    """
    return input("Vhi 2FA Code Required. Enter OTP: ").strip()

def main():
    # 1. Initialize the client
    # Replace with your actual credentials
    username = os.getenv("VHI_USERNAME", "your_email@example.com")
    password = os.getenv("VHI_PASSWORD", "your_password")
    
    # We pass our callback function so the client can automatically 
    # pause and invoke it if the server demands MFA.
    client = VhiClient(
        username=username, 
        password=password, 
        mfa_callback=my_cli_mfa_callback
    )

    try:
        # 2. Login
        print("Logging in...")
        client.login()
        print("Login successful!")

        # 3. Retrieve Claims
        print("\nRetrieving claims...")
        statements = client.get_claims()
        
        if not statements:
            print("No claim statements found.")
            return

        for claim in statements:
            print(f"- Claim {claim.claim_id} | Date: {claim.date_of_service} | Status: {claim.status}")

        # 4. Download a Document
        # We will download the first available document as an example
        first_claim = statements[0]
        if first_claim.document_id:
            download_path = f"{first_claim.claim_id}.pdf"
            print(f"\nDownloading document {first_claim.document_id} to {download_path}...")
            client.download_document(first_claim.document_id, download_path)
            print("Download complete!")

    except VhiAuthenticationError as e:
        print(f"Authentication failed: {e}")
    except VhiApiError as e:
        print(f"API Error occurred: {e}")

if __name__ == "__main__":
    main()
```

## Error Handling

The library provides structural custom exceptions:
- `VhiAuthenticationError`: Raised when login fails due to invalid credentials.
- `VhiMfaRequiredError`: Raised when the server requests MFA but you didn't provide a callback, or when the callback returns an invalid OTP.
- `VhiApiError`: Raised for any other 4xx or 5xx API errors. Contains standard HTTP status codes for debugging.
