"""
DLP-lite - Regex-based Classifiers
"""

import re
from typing import List
from .base import BaseClassifier
from ..models import ClassifierConfig, ClassifierMatch, ClassifierType, Severity


class RegexClassifier(BaseClassifier):
    """
    Pattern-based classifier using regex.
    """
    
    def __init__(self, config: ClassifierConfig):
        super().__init__(config)
        self._pattern = re.compile(config.pattern, re.IGNORECASE) if config.pattern else None
    
    def scan(self, content: str) -> List[ClassifierMatch]:
        """Scan content using regex pattern."""
        if not self._pattern:
            return []
        
        matches = []
        for match in self._pattern.finditer(content):
            matched_text = match.group()
            matches.append(ClassifierMatch(
                classifier_name=self.name,
                severity=self.severity,
                matched_text=matched_text,
                masked_text=self.mask(matched_text),
                position=match.start(),
                length=len(matched_text),
                context=self.get_context(content, match.start(), len(matched_text))
            ))
        
        return matches


# ============================================
# Pre-built Regex Classifiers
# ============================================

SSN_CLASSIFIER = RegexClassifier(ClassifierConfig(
    name="ssn",
    description="US Social Security Number",
    classifier_type=ClassifierType.REGEX,
    pattern=r"\b\d{3}-\d{2}-\d{4}\b",
    severity=Severity.HIGH
))

CREDIT_CARD_CLASSIFIER = RegexClassifier(ClassifierConfig(
    name="credit_card",
    description="Credit Card Number (basic pattern)",
    classifier_type=ClassifierType.REGEX,
    pattern=r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    severity=Severity.HIGH
))

EMAIL_CLASSIFIER = RegexClassifier(ClassifierConfig(
    name="email",
    description="Email Address",
    classifier_type=ClassifierType.REGEX,
    pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    severity=Severity.MEDIUM
))

PHONE_CLASSIFIER = RegexClassifier(ClassifierConfig(
    name="phone_us",
    description="US Phone Number",
    classifier_type=ClassifierType.REGEX,
    pattern=r"\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
    severity=Severity.MEDIUM
))

AWS_KEY_CLASSIFIER = RegexClassifier(ClassifierConfig(
    name="aws_access_key",
    description="AWS Access Key ID",
    classifier_type=ClassifierType.REGEX,
    pattern=r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b",
    severity=Severity.CRITICAL
))

AWS_SECRET_CLASSIFIER = RegexClassifier(ClassifierConfig(
    name="aws_secret_key",
    description="AWS Secret Access Key",
    classifier_type=ClassifierType.REGEX,
    pattern=r"\b[A-Za-z0-9/+=]{40}\b",
    severity=Severity.CRITICAL,
    context_required=True,
    context_patterns=["aws", "secret", "key"]
))

PRIVATE_KEY_CLASSIFIER = RegexClassifier(ClassifierConfig(
    name="private_key",
    description="Private Key (PEM format)",
    classifier_type=ClassifierType.REGEX,
    pattern=r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
    severity=Severity.CRITICAL
))

API_KEY_CLASSIFIER = RegexClassifier(ClassifierConfig(
    name="api_key",
    description="API Key (common patterns)",
    classifier_type=ClassifierType.REGEX,
    pattern=r"\b(?:sk_live|pk_live|api_key|apikey|api-key)[_\-]?[A-Za-z0-9]{20,}\b",
    severity=Severity.CRITICAL
))

PASSWORD_CLASSIFIER = RegexClassifier(ClassifierConfig(
    name="password_in_text",
    description="Password in text",
    classifier_type=ClassifierType.REGEX,
    pattern=r"(?:password|passwd|pwd|secret|token)\s*[=:]\s*['\"]?[^\s'\"]{4,}['\"]?",
    severity=Severity.HIGH
))

IP_ADDRESS_CLASSIFIER = RegexClassifier(ClassifierConfig(
    name="ip_address",
    description="IP Address (v4)",
    classifier_type=ClassifierType.REGEX,
    pattern=r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    severity=Severity.LOW
))


# Registry
REGEX_CLASSIFIERS = {
    "ssn": SSN_CLASSIFIER,
    "credit_card": CREDIT_CARD_CLASSIFIER,
    "email": EMAIL_CLASSIFIER,
    "phone_us": PHONE_CLASSIFIER,
    "aws_access_key": AWS_KEY_CLASSIFIER,
    "aws_secret_key": AWS_SECRET_CLASSIFIER,
    "private_key": PRIVATE_KEY_CLASSIFIER,
    "api_key": API_KEY_CLASSIFIER,
    "password_in_text": PASSWORD_CLASSIFIER,
    "ip_address": IP_ADDRESS_CLASSIFIER,
}
