"""
DLP-lite - Checksum-based Classifiers
Validates patterns using checksums (Luhn, etc.)
"""

import re
from typing import List
from .base import BaseClassifier
from ..models import ClassifierConfig, ClassifierMatch, ClassifierType, Severity


def luhn_check(number: str) -> bool:
    """
    Validate number using Luhn algorithm.
    Used for credit cards, IMEI, etc.
    """
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 2:
        return False
    
    # Double every second digit from right
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    
    return total % 10 == 0


class ChecksumClassifier(BaseClassifier):
    """
    Classifier that validates patterns using checksums.
    """
    
    def __init__(self, config: ClassifierConfig, checksum_func):
        super().__init__(config)
        self._pattern = re.compile(config.pattern, re.IGNORECASE) if config.pattern else None
        self._checksum_func = checksum_func
    
    def scan(self, content: str) -> List[ClassifierMatch]:
        """Scan content and validate with checksum."""
        if not self._pattern:
            return []
        
        matches = []
        for match in self._pattern.finditer(content):
            matched_text = match.group()
            
            # Validate checksum
            if self._checksum_func(matched_text):
                matches.append(ClassifierMatch(
                    classifier_name=self.name,
                    severity=self.severity,
                    matched_text=matched_text,
                    masked_text=self.mask(matched_text),
                    position=match.start(),
                    length=len(matched_text),
                    confidence=1.0,  # Checksum validated
                    context=self.get_context(content, match.start(), len(matched_text))
                ))
        
        return matches


# ============================================
# Pre-built Checksum Classifiers
# ============================================

CREDIT_CARD_LUHN_CLASSIFIER = ChecksumClassifier(
    ClassifierConfig(
        name="credit_card_valid",
        description="Valid Credit Card Number (Luhn verified)",
        classifier_type=ClassifierType.CHECKSUM,
        pattern=r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        severity=Severity.HIGH
    ),
    luhn_check
)

SSN_VALIDATED_CLASSIFIER = ChecksumClassifier(
    ClassifierConfig(
        name="ssn_validated",
        description="Valid SSN (area number validated)",
        classifier_type=ClassifierType.CHECKSUM,
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        severity=Severity.HIGH
    ),
    lambda ssn: (
        # SSN area number validation (not starting with 000, 666, or 900-999)
        ssn.replace("-", "")[:3] not in ["000", "666"] and
        not ssn.replace("-", "")[:3].startswith("9") and
        ssn.replace("-", "")[3:5] != "00" and
        ssn.replace("-", "")[5:9] != "0000"
    )
)


CHECKSUM_CLASSIFIERS = {
    "credit_card_valid": CREDIT_CARD_LUHN_CLASSIFIER,
    "ssn_validated": SSN_VALIDATED_CLASSIFIER,
}
