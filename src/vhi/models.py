from dataclasses import dataclass
from typing import Optional

@dataclass
class ClaimStatement:
    claim_id: str
    date_of_service: str
    practitioner: str
    document_id: str
    status: str
    
    @classmethod
    def from_dict(cls, data: dict) -> "ClaimStatement":
        return cls(
            claim_id=data.get("claimId", ""),
            date_of_service=data.get("dateOfService", ""),
            practitioner=data.get("practitioner", ""),
            document_id=data.get("documentId", ""),
            status=data.get("status", "")
        )
