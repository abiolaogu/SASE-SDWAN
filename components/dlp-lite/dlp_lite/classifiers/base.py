"""
DLP-lite - Base Classifier Interface
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from ..models import ClassifierConfig, ClassifierMatch, Severity


class BaseClassifier(ABC):
    """
    Base interface for content classifiers.
    """
    
    def __init__(self, config: ClassifierConfig):
        self.config = config
    
    @property
    def name(self) -> str:
        return self.config.name
    
    @property
    def severity(self) -> Severity:
        return self.config.severity
    
    @property
    def enabled(self) -> bool:
        return self.config.enabled
    
    @abstractmethod
    def scan(self, content: str) -> List[ClassifierMatch]:
        """
        Scan content for matches.
        
        Args:
            content: Text content to scan
            
        Returns:
            List of matches found
        """
        pass
    
    def mask(self, text: str) -> str:
        """
        Mask sensitive text for display.
        """
        if len(text) <= 4:
            return "****"
        return text[:2] + "*" * (len(text) - 4) + text[-2:]
    
    def get_context(self, content: str, position: int, length: int, window: int = 20) -> str:
        """
        Get context around a match.
        """
        start = max(0, position - window)
        end = min(len(content), position + length + window)
        return content[start:end]
