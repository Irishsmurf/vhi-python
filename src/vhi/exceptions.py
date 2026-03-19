class VhiError(Exception):
    """Base exception for Vhi Python Client"""
    pass

class VhiAuthenticationError(VhiError):
    """Raised when authentication fails (invalid credentials)"""
    pass

class VhiMfaRequiredError(VhiError):
    """Raised when MFA is required but no callback is provided or callback fails"""
    pass

class VhiApiError(VhiError):
    """Raised when the Vhi API returns an error response"""
    def __init__(self, message, status_code=None, response=None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response
