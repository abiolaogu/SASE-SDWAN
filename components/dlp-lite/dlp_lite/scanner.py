"""
DLP-lite - Content Scanner
"""

import time
from typing import List, Optional
from .models import ScanRequest, ScanResult, ClassifierMatch, Severity, ScanSource
from .classifiers import ALL_CLASSIFIERS, get_classifier


class ContentScanner:
    """
    Scans content using configured classifiers.
    """
    
    def __init__(self, classifiers: Optional[List[str]] = None):
        """
        Initialize scanner.
        
        Args:
            classifiers: List of classifier names to use. None = all.
        """
        if classifiers:
            self._classifiers = [get_classifier(name) for name in classifiers]
        else:
            self._classifiers = list(ALL_CLASSIFIERS.values())
    
    def scan(self, request: ScanRequest) -> ScanResult:
        """
        Scan content for sensitive data.
        """
        start_time = time.time()
        matches = []
        
        # Run each classifier
        for classifier in self._classifiers:
            if not classifier.enabled:
                continue
            
            try:
                classifier_matches = classifier.scan(request.content)
                matches.extend(classifier_matches)
            except Exception as e:
                # Log but continue
                continue
        
        # Deduplicate overlapping matches
        matches = self._deduplicate(matches)
        
        # Determine highest severity
        highest = None
        if matches:
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
            for sev in severity_order:
                if any(m.severity == sev for m in matches):
                    highest = sev
                    break
        
        scan_time = (time.time() - start_time) * 1000
        
        return ScanResult(
            source=request.source,
            filename=request.filename,
            content_length=len(request.content),
            scan_time_ms=round(scan_time, 2),
            matches=matches,
            highest_severity=highest,
            has_sensitive_data=len(matches) > 0
        )
    
    def scan_text(self, text: str, source: ScanSource = ScanSource.TEXT) -> ScanResult:
        """Convenience method to scan text."""
        return self.scan(ScanRequest(content=text, source=source))
    
    def scan_file(self, filepath: str) -> ScanResult:
        """Scan a file."""
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        return self.scan(ScanRequest(
            content=content,
            source=ScanSource.FILE,
            filename=filepath
        ))
    
    def _deduplicate(self, matches: List[ClassifierMatch]) -> List[ClassifierMatch]:
        """
        Remove overlapping matches, keeping higher severity.
        """
        if len(matches) <= 1:
            return matches
        
        # Sort by position
        matches.sort(key=lambda m: (m.position, -len(m.matched_text)))
        
        result = []
        for match in matches:
            # Check if this match overlaps with existing
            overlaps = False
            for existing in result:
                if self._overlaps(match, existing):
                    # Keep higher severity
                    if self._is_higher_severity(match.severity, existing.severity):
                        result.remove(existing)
                    else:
                        overlaps = True
                        break
            
            if not overlaps:
                result.append(match)
        
        return result
    
    def _overlaps(self, a: ClassifierMatch, b: ClassifierMatch) -> bool:
        """Check if two matches overlap."""
        a_end = a.position + a.length
        b_end = b.position + b.length
        return not (a_end <= b.position or b_end <= a.position)
    
    def _is_higher_severity(self, a: Severity, b: Severity) -> bool:
        """Check if severity a is higher than b."""
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return order.index(a) < order.index(b)
