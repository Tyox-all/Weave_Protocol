"""
Weave Protocol LlamaIndex - Type Definitions
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union


class Severity(str, Enum):
    """Security finding severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    """Types of security threats detected."""
    PROMPT_INJECTION = "prompt_injection"
    PII_EXPOSURE = "pii_exposure"
    SECRET_LEAK = "secret_leak"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    MALICIOUS_URL = "malicious_url"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SENSITIVE_TOPIC = "sensitive_topic"


class ActionType(str, Enum):
    """Actions taken in response to security findings."""
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    WARN = "warn"
    LOG = "log"


@dataclass
class SecurityFinding:
    """A single security finding from scanning."""
    threat_type: ThreatType
    severity: Severity
    description: str
    location: str
    matched_pattern: Optional[str] = None
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


def _utcnow() -> datetime:
    """Return current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


@dataclass
class ScanResult:
    """Result of a security scan."""
    is_safe: bool
    findings: List[SecurityFinding] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=_utcnow)
    scan_duration_ms: float = 0.0
    content_hash: Optional[str] = None
    
    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)
    
    @property
    def has_high(self) -> bool:
        return any(f.severity == Severity.HIGH for f in self.findings)
    
    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for sev in severity_order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None


@dataclass
class SecurityEvent:
    """Security event for logging and callbacks."""
    event_type: str
    timestamp: datetime
    scan_result: Optional[ScanResult]
    action_taken: ActionType
    content_preview: Optional[str] = None
    tool_name: Optional[str] = None
    trace_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityConfig:
    """Configuration for security scanning behavior."""
    # Blocking thresholds
    block_on_critical: bool = True
    block_on_high: bool = True
    block_on_medium: bool = False
    block_on_low: bool = False
    
    # Scanning options
    scan_inputs: bool = True
    scan_outputs: bool = True
    scan_tool_calls: bool = True
    scan_retrieved_docs: bool = True
    
    # PII handling
    redact_pii: bool = False
    pii_types_to_redact: List[str] = field(default_factory=lambda: [
        "email", "phone", "ssn", "credit_card", "api_key"
    ])
    
    # Performance
    max_content_length: int = 100000
    timeout_seconds: float = 30.0
    
    # Callbacks
    on_threat_detected: Optional[Callable[[SecurityEvent], None]] = None
    on_scan_complete: Optional[Callable[[ScanResult], None]] = None
    
    def should_block(self, result: ScanResult) -> bool:
        """Determine if the result should trigger a block."""
        if not result.findings:
            return False
        
        for finding in result.findings:
            if finding.severity == Severity.CRITICAL and self.block_on_critical:
                return True
            if finding.severity == Severity.HIGH and self.block_on_high:
                return True
            if finding.severity == Severity.MEDIUM and self.block_on_medium:
                return True
            if finding.severity == Severity.LOW and self.block_on_low:
                return True
        
        return False


# Type aliases
ApprovalCallback = Callable[[str, str, Dict[str, Any]], bool]
RedactionCallback = Callable[[str, List[SecurityFinding]], str]
