"""
Weave Protocol LlamaIndex - Security Callback Handler
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from llama_index.core.callbacks import CBEventType
from llama_index.core.callbacks.base_handler import BaseCallbackHandler

from .scanner import BaseScanner, LocalScanner
from .types import (
    ActionType,
    ScanResult,
    SecurityConfig,
    SecurityEvent,
    SecurityFinding,
    Severity,
)


class WeaveSecurityHandler(BaseCallbackHandler):
    """
    LlamaIndex callback handler for security scanning.
    
    Intercepts LlamaIndex events and scans content for security threats.
    Can be configured to block, warn, or log threats.
    
    Usage:
        from weave_protocol_llamaindex import WeaveSecurityHandler
        from llama_index.core.callbacks import CallbackManager
        
        security_handler = WeaveSecurityHandler()
        callback_manager = CallbackManager([security_handler])
        
        # Use with Settings
        from llama_index.core import Settings
        Settings.callback_manager = callback_manager
    """
    
    def __init__(
        self,
        scanner: Optional[BaseScanner] = None,
        config: Optional[SecurityConfig] = None,
        event_starts_to_ignore: Optional[List[CBEventType]] = None,
        event_ends_to_ignore: Optional[List[CBEventType]] = None,
    ):
        """
        Initialize the security handler.
        
        Args:
            scanner: Security scanner to use (defaults to LocalScanner)
            config: Security configuration
            event_starts_to_ignore: Event types to ignore on start
            event_ends_to_ignore: Event types to ignore on end
        """
        super().__init__(
            event_starts_to_ignore=event_starts_to_ignore or [],
            event_ends_to_ignore=event_ends_to_ignore or [],
        )
        
        self.scanner = scanner or LocalScanner()
        self.config = config or SecurityConfig()
        
        # Event tracking
        self.events: List[SecurityEvent] = []
        self.blocked_count = 0
        self.warned_count = 0
        self.total_scans = 0
    
    def on_event_start(
        self,
        event_type: CBEventType,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        """
        Handle event start - scan inputs.
        
        Args:
            event_type: Type of LlamaIndex event
            payload: Event payload data
            event_id: Unique event ID
            parent_id: Parent event ID
            
        Returns:
            Event ID
        """
        if not self.config.scan_inputs:
            return event_id
        
        content_to_scan = self._extract_content(event_type, payload, is_start=True)
        
        if content_to_scan:
            self._scan_and_handle(
                content=content_to_scan,
                event_type=event_type,
                event_id=event_id,
                location=f"input:{event_type.value}",
            )
        
        return event_id
    
    def on_event_end(
        self,
        event_type: CBEventType,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        """
        Handle event end - scan outputs.
        
        Args:
            event_type: Type of LlamaIndex event
            payload: Event payload data
            event_id: Unique event ID
        """
        if not self.config.scan_outputs:
            return
        
        content_to_scan = self._extract_content(event_type, payload, is_start=False)
        
        if content_to_scan:
            self._scan_and_handle(
                content=content_to_scan,
                event_type=event_type,
                event_id=event_id,
                location=f"output:{event_type.value}",
            )
    
    def start_trace(self, trace_id: Optional[str] = None) -> None:
        """Called when a trace starts."""
        pass
    
    def end_trace(
        self,
        trace_id: Optional[str] = None,
        trace_map: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        """Called when a trace ends."""
        pass
    
    def _extract_content(
        self,
        event_type: CBEventType,
        payload: Optional[Dict[str, Any]],
        is_start: bool,
    ) -> Optional[str]:
        """
        Extract scannable content from event payload.
        
        Args:
            event_type: Type of event
            payload: Event payload
            is_start: Whether this is event start or end
            
        Returns:
            Content string to scan, or None
        """
        if not payload:
            return None
        
        content_parts: List[str] = []
        
        # LLM events
        if event_type == CBEventType.LLM:
            if is_start:
                # Scan the prompt/messages
                if "messages" in payload:
                    for msg in payload["messages"]:
                        if hasattr(msg, "content"):
                            content_parts.append(str(msg.content))
                        elif isinstance(msg, dict) and "content" in msg:
                            content_parts.append(str(msg["content"]))
                if "prompt" in payload:
                    content_parts.append(str(payload["prompt"]))
            else:
                # Scan the response
                if "response" in payload:
                    resp = payload["response"]
                    if hasattr(resp, "text"):
                        content_parts.append(resp.text)
                    elif hasattr(resp, "message") and hasattr(resp.message, "content"):
                        content_parts.append(str(resp.message.content))
                    elif isinstance(resp, str):
                        content_parts.append(resp)
        
        # Embedding events
        elif event_type == CBEventType.EMBEDDING:
            if is_start and "chunks" in payload:
                content_parts.extend([str(c) for c in payload["chunks"]])
        
        # Query events
        elif event_type == CBEventType.QUERY:
            if is_start and "query_str" in payload:
                content_parts.append(str(payload["query_str"]))
        
        # Retrieve events
        elif event_type == CBEventType.RETRIEVE:
            if not is_start and "nodes" in payload:
                for node in payload["nodes"]:
                    if hasattr(node, "text"):
                        content_parts.append(node.text)
                    elif hasattr(node, "node") and hasattr(node.node, "text"):
                        content_parts.append(node.node.text)
        
        # Chunking/parsing events
        elif event_type in (CBEventType.CHUNKING, CBEventType.NODE_PARSING):
            if "documents" in payload:
                for doc in payload["documents"]:
                    if hasattr(doc, "text"):
                        content_parts.append(doc.text)
            if "chunks" in payload:
                content_parts.extend([str(c) for c in payload["chunks"]])
        
        # Function/tool calls
        elif event_type == CBEventType.FUNCTION_CALL:
            if is_start:
                if "function" in payload:
                    content_parts.append(str(payload["function"]))
                if "args" in payload:
                    content_parts.append(str(payload["args"]))
            else:
                if "output" in payload:
                    content_parts.append(str(payload["output"]))
        
        if content_parts:
            combined = "\n".join(content_parts)
            # Truncate if too long
            if len(combined) > self.config.max_content_length:
                combined = combined[:self.config.max_content_length]
            return combined
        
        return None
    
    def _scan_and_handle(
        self,
        content: str,
        event_type: CBEventType,
        event_id: str,
        location: str,
    ) -> ScanResult:
        """
        Scan content and handle the result.
        
        Args:
            content: Content to scan
            event_type: Event type
            event_id: Event ID
            location: Location description
            
        Returns:
            Scan result
        """
        self.total_scans += 1
        
        result = self.scanner.scan(content, context={"location": location})
        
        # Determine action
        if self.config.should_block(result):
            action = ActionType.BLOCK
            self.blocked_count += 1
        elif result.findings:
            action = ActionType.WARN
            self.warned_count += 1
        else:
            action = ActionType.ALLOW
        
        # Create security event
        event = SecurityEvent(
            event_type=event_type.value,
            timestamp=datetime.now(timezone.utc),
            scan_result=result,
            action_taken=action,
            content_preview=content[:100] if content else None,
            trace_id=event_id,
        )
        self.events.append(event)
        
        # Call callbacks
        if result.findings and self.config.on_threat_detected:
            self.config.on_threat_detected(event)
        
        if self.config.on_scan_complete:
            self.config.on_scan_complete(result)
        
        # Raise if blocking
        if action == ActionType.BLOCK:
            raise SecurityBlockError(
                f"Security threat detected: {result.findings[0].description}",
                result=result,
            )
        
        return result
    
    def get_stats(self) -> Dict[str, Any]:
        """Get security statistics."""
        return {
            "total_scans": self.total_scans,
            "blocked_count": self.blocked_count,
            "warned_count": self.warned_count,
            "events_count": len(self.events),
            "threats_by_type": self._count_threats_by_type(),
            "threats_by_severity": self._count_threats_by_severity(),
        }
    
    def _count_threats_by_type(self) -> Dict[str, int]:
        """Count threats by type across all events."""
        counts: Dict[str, int] = {}
        for event in self.events:
            if event.scan_result:
                for finding in event.scan_result.findings:
                    key = finding.threat_type.value
                    counts[key] = counts.get(key, 0) + 1
        return counts
    
    def _count_threats_by_severity(self) -> Dict[str, int]:
        """Count threats by severity across all events."""
        counts: Dict[str, int] = {}
        for event in self.events:
            if event.scan_result:
                for finding in event.scan_result.findings:
                    key = finding.severity.value
                    counts[key] = counts.get(key, 0) + 1
        return counts
    
    def clear_events(self) -> None:
        """Clear stored events."""
        self.events.clear()
    
    def get_recent_threats(self, limit: int = 10) -> List[SecurityFinding]:
        """Get recent threat findings."""
        findings: List[SecurityFinding] = []
        for event in reversed(self.events):
            if event.scan_result and event.scan_result.findings:
                findings.extend(event.scan_result.findings)
                if len(findings) >= limit:
                    break
        return findings[:limit]


class SecurityBlockError(Exception):
    """Exception raised when content is blocked due to security concerns."""
    
    def __init__(self, message: str, result: ScanResult):
        super().__init__(message)
        self.result = result
        self.findings = result.findings


# Preset configurations
def create_strict_handler(scanner: Optional[BaseScanner] = None) -> WeaveSecurityHandler:
    """Create a handler that blocks on medium+ severity threats."""
    config = SecurityConfig(
        block_on_critical=True,
        block_on_high=True,
        block_on_medium=True,
        block_on_low=False,
    )
    return WeaveSecurityHandler(scanner=scanner, config=config)


def create_warning_handler(scanner: Optional[BaseScanner] = None) -> WeaveSecurityHandler:
    """Create a handler that only logs threats (no blocking)."""
    config = SecurityConfig(
        block_on_critical=False,
        block_on_high=False,
        block_on_medium=False,
        block_on_low=False,
    )
    return WeaveSecurityHandler(scanner=scanner, config=config)


def create_production_handler(scanner: Optional[BaseScanner] = None) -> WeaveSecurityHandler:
    """Create a handler suitable for production (blocks high+ severity)."""
    config = SecurityConfig(
        block_on_critical=True,
        block_on_high=True,
        block_on_medium=False,
        block_on_low=False,
        scan_inputs=True,
        scan_outputs=True,
    )
    return WeaveSecurityHandler(scanner=scanner, config=config)
