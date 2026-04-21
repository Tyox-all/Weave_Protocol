"""
Weave Protocol LlamaIndex - Security Scanners
"""

import hashlib
import re
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Pattern

from .types import (
    ScanResult,
    SecurityFinding,
    Severity,
    ThreatType,
)


class BaseScanner(ABC):
    """Abstract base class for security scanners."""
    
    @abstractmethod
    def scan(self, content: str, context: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan content for security threats."""
        pass
    
    @abstractmethod
    async def scan_async(self, content: str, context: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Async version of scan."""
        pass


class PatternDefinition:
    """Definition of a security pattern to detect."""
    
    def __init__(
        self,
        name: str,
        pattern: str,
        threat_type: ThreatType,
        severity: Severity,
        description: str,
        flags: int = re.IGNORECASE,
    ):
        self.name = name
        self.pattern = pattern
        self.compiled: Pattern = re.compile(pattern, flags)
        self.threat_type = threat_type
        self.severity = severity
        self.description = description


# Default security patterns
DEFAULT_PATTERNS: List[PatternDefinition] = [
    # Prompt injection patterns
    PatternDefinition(
        name="ignore_instructions",
        pattern=r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        description="Attempt to override system instructions",
    ),
    PatternDefinition(
        name="new_instructions",
        pattern=r"(new|your\s+new|updated?)\s+(instructions?|rules?|role)\s*(are|is|:)",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        description="Attempt to inject new instructions",
    ),
    PatternDefinition(
        name="system_prompt_leak",
        pattern=r"(reveal|show|display|output|print|tell\s+me)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?)",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.MEDIUM,
        description="Attempt to extract system prompt",
    ),
    PatternDefinition(
        name="role_override",
        pattern=r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\'?re)|roleplay\s+as)",
        threat_type=ThreatType.JAILBREAK_ATTEMPT,
        severity=Severity.MEDIUM,
        description="Attempt to override AI role",
    ),
    PatternDefinition(
        name="dan_jailbreak",
        pattern=r"(DAN|do\s+anything\s+now|jailbreak|bypass\s+restrictions)",
        threat_type=ThreatType.JAILBREAK_ATTEMPT,
        severity=Severity.HIGH,
        description="Known jailbreak technique",
    ),
    
    # PII patterns
    PatternDefinition(
        name="email",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        threat_type=ThreatType.PII_EXPOSURE,
        severity=Severity.MEDIUM,
        description="Email address detected",
        flags=0,
    ),
    PatternDefinition(
        name="phone_us",
        pattern=r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        threat_type=ThreatType.PII_EXPOSURE,
        severity=Severity.MEDIUM,
        description="US phone number detected",
        flags=0,
    ),
    PatternDefinition(
        name="ssn",
        pattern=r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        threat_type=ThreatType.PII_EXPOSURE,
        severity=Severity.CRITICAL,
        description="Social Security Number detected",
        flags=0,
    ),
    PatternDefinition(
        name="credit_card",
        pattern=r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        threat_type=ThreatType.PII_EXPOSURE,
        severity=Severity.CRITICAL,
        description="Credit card number detected",
        flags=0,
    ),
    
    # Secret patterns
    PatternDefinition(
        name="api_key_generic",
        pattern=r"\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?",
        threat_type=ThreatType.SECRET_LEAK,
        severity=Severity.CRITICAL,
        description="API key or token detected",
    ),
    PatternDefinition(
        name="aws_key",
        pattern=r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
        threat_type=ThreatType.SECRET_LEAK,
        severity=Severity.CRITICAL,
        description="AWS access key detected",
        flags=0,
    ),
    PatternDefinition(
        name="private_key",
        pattern=r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        threat_type=ThreatType.SECRET_LEAK,
        severity=Severity.CRITICAL,
        description="Private key detected",
    ),
    PatternDefinition(
        name="password_in_text",
        pattern=r"(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?",
        threat_type=ThreatType.SECRET_LEAK,
        severity=Severity.HIGH,
        description="Password in plaintext detected",
    ),
    
    # Injection patterns
    PatternDefinition(
        name="sql_injection",
        pattern=r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*\b(FROM|INTO|WHERE|TABLE)\b)|(';\s*--|'\s+OR\s+'1'\s*=\s*'1)",
        threat_type=ThreatType.SQL_INJECTION,
        severity=Severity.HIGH,
        description="Potential SQL injection",
    ),
    PatternDefinition(
        name="command_injection",
        pattern=r"[;&|`$]\s*(cat|ls|rm|wget|curl|bash|sh|python|perl|nc|netcat)\s",
        threat_type=ThreatType.COMMAND_INJECTION,
        severity=Severity.HIGH,
        description="Potential command injection",
    ),
    PatternDefinition(
        name="path_traversal",
        pattern=r"\.\.[\\/]|\.\.%2[fF]|%2e%2e[\\/]",
        threat_type=ThreatType.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        description="Path traversal attempt",
    ),
]


class LocalScanner(BaseScanner):
    """
    Local pattern-based security scanner.
    
    Scans content using regex patterns to detect security threats.
    No external dependencies required.
    """
    
    def __init__(
        self,
        patterns: Optional[List[PatternDefinition]] = None,
        additional_patterns: Optional[List[PatternDefinition]] = None,
        disabled_patterns: Optional[List[str]] = None,
    ):
        """
        Initialize the local scanner.
        
        Args:
            patterns: Custom patterns to use instead of defaults
            additional_patterns: Patterns to add to defaults
            disabled_patterns: Pattern names to disable
        """
        self.patterns = patterns or DEFAULT_PATTERNS.copy()
        
        if additional_patterns:
            self.patterns.extend(additional_patterns)
        
        if disabled_patterns:
            self.patterns = [p for p in self.patterns if p.name not in disabled_patterns]
    
    def scan(self, content: str, context: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Scan content for security threats.
        
        Args:
            content: The text content to scan
            context: Optional context about where content came from
            
        Returns:
            ScanResult with findings
        """
        start_time = time.time()
        findings: List[SecurityFinding] = []
        
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        location = context.get("location", "unknown") if context else "unknown"
        
        for pattern in self.patterns:
            matches = pattern.compiled.findall(content)
            if matches:
                # Deduplicate matches
                unique_matches = list(set(
                    m if isinstance(m, str) else m[0] if m else ""
                    for m in matches
                ))
                
                for match in unique_matches[:5]:  # Limit to 5 per pattern
                    findings.append(SecurityFinding(
                        threat_type=pattern.threat_type,
                        severity=pattern.severity,
                        description=pattern.description,
                        location=location,
                        matched_pattern=pattern.name,
                        confidence=0.9,
                        metadata={"match_preview": match[:50] if match else None}
                    ))
        
        duration_ms = (time.time() - start_time) * 1000
        
        return ScanResult(
            is_safe=len(findings) == 0,
            findings=findings,
            scanned_at=datetime.now(timezone.utc),
            scan_duration_ms=duration_ms,
            content_hash=content_hash,
        )
    
    async def scan_async(self, content: str, context: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Async version - delegates to sync implementation."""
        return self.scan(content, context)


class RemoteScanner(BaseScanner):
    """
    Remote scanner that calls Weave Protocol API.
    
    Requires the 'remote' extra: pip install weave-protocol-llamaindex[remote]
    """
    
    def __init__(
        self,
        api_url: str = "http://localhost:3000",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """
        Initialize the remote scanner.
        
        Args:
            api_url: URL of the Weave Protocol API
            api_key: Optional API key for authentication
            timeout: Request timeout in seconds
        """
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._client = None
    
    def _get_client(self):
        """Lazy initialization of HTTP client."""
        if self._client is None:
            try:
                import httpx
            except ImportError:
                raise ImportError(
                    "httpx is required for RemoteScanner. "
                    "Install with: pip install weave-protocol-llamaindex[remote]"
                )
            
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            self._client = httpx.Client(
                base_url=self.api_url,
                headers=headers,
                timeout=self.timeout,
            )
        
        return self._client
    
    def _get_async_client(self):
        """Get async HTTP client."""
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for RemoteScanner. "
                "Install with: pip install weave-protocol-llamaindex[remote]"
            )
        
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        return httpx.AsyncClient(
            base_url=self.api_url,
            headers=headers,
            timeout=self.timeout,
        )
    
    def scan(self, content: str, context: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan content via remote API."""
        start_time = time.time()
        client = self._get_client()
        
        response = client.post(
            "/api/mund/scan",
            json={
                "content": content,
                "context": context or {},
            }
        )
        response.raise_for_status()
        data = response.json()
        
        findings = [
            SecurityFinding(
                threat_type=ThreatType(f["threat_type"]),
                severity=Severity(f["severity"]),
                description=f["description"],
                location=f.get("location", "remote"),
                matched_pattern=f.get("matched_pattern"),
                confidence=f.get("confidence", 1.0),
            )
            for f in data.get("findings", [])
        ]
        
        duration_ms = (time.time() - start_time) * 1000
        
        return ScanResult(
            is_safe=data.get("is_safe", len(findings) == 0),
            findings=findings,
            scanned_at=datetime.now(timezone.utc),
            scan_duration_ms=duration_ms,
            content_hash=data.get("content_hash"),
        )
    
    async def scan_async(self, content: str, context: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Async scan via remote API."""
        start_time = time.time()
        
        async with self._get_async_client() as client:
            response = await client.post(
                "/api/mund/scan",
                json={
                    "content": content,
                    "context": context or {},
                }
            )
            response.raise_for_status()
            data = response.json()
        
        findings = [
            SecurityFinding(
                threat_type=ThreatType(f["threat_type"]),
                severity=Severity(f["severity"]),
                description=f["description"],
                location=f.get("location", "remote"),
                matched_pattern=f.get("matched_pattern"),
                confidence=f.get("confidence", 1.0),
            )
            for f in data.get("findings", [])
        ]
        
        duration_ms = (time.time() - start_time) * 1000
        
        return ScanResult(
            is_safe=data.get("is_safe", len(findings) == 0),
            findings=findings,
            scanned_at=datetime.now(timezone.utc),
            scan_duration_ms=duration_ms,
            content_hash=data.get("content_hash"),
        )


def create_scanner(
    mode: str = "local",
    **kwargs,
) -> BaseScanner:
    """
    Factory function to create a scanner.
    
    Args:
        mode: "local" or "remote"
        **kwargs: Arguments passed to scanner constructor
        
    Returns:
        Configured scanner instance
    """
    if mode == "local":
        return LocalScanner(**kwargs)
    elif mode == "remote":
        return RemoteScanner(**kwargs)
    else:
        raise ValueError(f"Unknown scanner mode: {mode}")
