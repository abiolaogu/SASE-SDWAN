"""DLP-lite Classifiers Package"""

from .base import BaseClassifier
from .regex import REGEX_CLASSIFIERS, RegexClassifier
from .checksum import CHECKSUM_CLASSIFIERS, ChecksumClassifier
from .entropy import ENTROPY_CLASSIFIERS, EntropyClassifier

# Combined registry of all classifiers
ALL_CLASSIFIERS = {
    **REGEX_CLASSIFIERS,
    **CHECKSUM_CLASSIFIERS,
    **ENTROPY_CLASSIFIERS,
}


def get_classifier(name: str) -> BaseClassifier:
    """Get classifier by name."""
    if name not in ALL_CLASSIFIERS:
        raise ValueError(f"Unknown classifier: {name}")
    return ALL_CLASSIFIERS[name]


def list_classifiers() -> list:
    """List all available classifiers."""
    return [
        {
            "name": clf.name,
            "description": clf.config.description,
            "severity": clf.severity.value,
            "type": clf.config.classifier_type.value
        }
        for clf in ALL_CLASSIFIERS.values()
    ]


__all__ = [
    "BaseClassifier",
    "RegexClassifier",
    "ChecksumClassifier", 
    "EntropyClassifier",
    "ALL_CLASSIFIERS",
    "get_classifier",
    "list_classifiers"
]
