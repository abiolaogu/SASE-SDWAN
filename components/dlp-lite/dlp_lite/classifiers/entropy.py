"""
DLP-lite - Entropy-based Classifiers
Detects high-entropy strings (potential secrets)
"""

import re
import math
from typing import List
from .base import BaseClassifier
from ..models import ClassifierConfig, ClassifierMatch, ClassifierType, Severity


def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher entropy = more random = more likely to be a secret.
    """
    if not data:
        return 0.0
    
    # Count character frequencies
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy


class EntropyClassifier(BaseClassifier):
    """
    Classifier that detects high-entropy strings.
    Useful for detecting secrets, API keys, tokens.
    """
    
    # Default thresholds
    MIN_LENGTH = 16
    MAX_LENGTH = 128
    
    def __init__(self, config: ClassifierConfig):
        super().__init__(config)
        self._threshold = config.entropy_threshold or 4.5
        self._pattern = re.compile(config.pattern) if config.pattern else None
    
    def scan(self, content: str) -> List[ClassifierMatch]:
        """Scan content for high-entropy strings."""
        matches = []
        
        # Use pattern if provided, otherwise scan all word-like tokens
        if self._pattern:
            candidates = self._pattern.finditer(content)
        else:
            candidates = re.finditer(r'\b[A-Za-z0-9+/=_-]{16,}\b', content)
        
        for match in candidates:
            text = match.group()
            
            if len(text) < self.MIN_LENGTH or len(text) > self.MAX_LENGTH:
                continue
            
            entropy = calculate_entropy(text)
            
            if entropy >= self._threshold:
                # Adjust confidence based on entropy level
                confidence = min(1.0, (entropy - self._threshold) / 2 + 0.5)
                
                matches.append(ClassifierMatch(
                    classifier_name=self.name,
                    severity=self.severity,
                    matched_text=text,
                    masked_text=self.mask(text),
                    position=match.start(),
                    length=len(text),
                    confidence=round(confidence, 2),
                    context=self.get_context(content, match.start(), len(text))
                ))
        
        return matches


# ============================================
# Pre-built Entropy Classifiers
# ============================================

HIGH_ENTROPY_SECRET = EntropyClassifier(ClassifierConfig(
    name="high_entropy_secret",
    description="High-entropy string (potential secret)",
    classifier_type=ClassifierType.ENTROPY,
    entropy_threshold=4.5,
    severity=Severity.HIGH
))

API_TOKEN_ENTROPY = EntropyClassifier(ClassifierConfig(
    name="api_token_entropy",
    description="API token (entropy-based detection)",
    classifier_type=ClassifierType.ENTROPY,
    pattern=r"(?:token|key|secret|api)[_\-]?[A-Za-z0-9_\-]{20,}",
    entropy_threshold=4.0,
    severity=Severity.CRITICAL
))

BASE64_SECRET = EntropyClassifier(ClassifierConfig(
    name="base64_secret",
    description="Base64-encoded secret",
    classifier_type=ClassifierType.ENTROPY,
    pattern=r"[A-Za-z0-9+/]{32,}={0,2}",
    entropy_threshold=5.0,
    severity=Severity.HIGH
))


ENTROPY_CLASSIFIERS = {
    "high_entropy_secret": HIGH_ENTROPY_SECRET,
    "api_token_entropy": API_TOKEN_ENTROPY,
    "base64_secret": BASE64_SECRET,
}
