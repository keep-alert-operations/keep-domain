"""Trusted directory evidence and backend-only OIDC protocol adapters."""

from .directory import DirectoryEvidence, DirectoryObject, DirectoryVerifier, PrincipalKey

__all__ = ["DirectoryEvidence", "DirectoryObject", "DirectoryVerifier", "PrincipalKey"]

from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)
