"""
Weave Protocol LlamaIndex - Secure Retriever
"""

import re
from typing import Any, Dict, List, Optional

from llama_index.core.base.base_retriever import BaseRetriever
from llama_index.core.schema import NodeWithScore, QueryBundle, TextNode

from .scanner import BaseScanner, LocalScanner
from .types import SecurityConfig, SecurityFinding, Severity, ThreatType


class SecureRetriever(BaseRetriever):
    """
    A secure wrapper around LlamaIndex retrievers.
    
    Scans retrieved documents for security threats and optionally redacts PII.
    
    Usage:
        from weave_protocol_llamaindex import SecureRetriever
        from llama_index.core import VectorStoreIndex
        
        index = VectorStoreIndex.from_documents(documents)
        base_retriever = index.as_retriever()
        
        secure_retriever = SecureRetriever(
            retriever=base_retriever,
            redact_pii=True
        )
    """
    
    def __init__(
        self,
        retriever: BaseRetriever,
        scanner: Optional[BaseScanner] = None,
        config: Optional[SecurityConfig] = None,
        filter_unsafe: bool = False,
        redact_pii: bool = False,
    ):
        """
        Initialize the secure retriever.
        
        Args:
            retriever: Base retriever to wrap
            scanner: Security scanner
            config: Security configuration
            filter_unsafe: If True, remove unsafe nodes from results
            redact_pii: If True, redact PII from retrieved content
        """
        super().__init__()
        self._retriever = retriever
        self._scanner = scanner or LocalScanner()
        self._config = config or SecurityConfig()
        self._filter_unsafe = filter_unsafe
        self._redact_pii = redact_pii
        
        # Stats
        self._retrieve_count = 0
        self._filtered_count = 0
        self._redacted_count = 0
    
    def _retrieve(self, query_bundle: QueryBundle) -> List[NodeWithScore]:
        """
        Retrieve and scan documents.
        
        Args:
            query_bundle: Query to retrieve for
            
        Returns:
            List of (possibly filtered/redacted) nodes
        """
        self._retrieve_count += 1
        
        # Get results from base retriever
        nodes = self._retriever.retrieve(query_bundle)
        
        # Scan query first
        if self._config.scan_inputs:
            query_result = self._scanner.scan(
                query_bundle.query_str,
                context={"location": "retriever_query"}
            )
            # Log but don't block queries - that would break RAG
            if query_result.findings:
                pass  # Could add callback here
        
        # Process each node
        processed_nodes: List[NodeWithScore] = []
        
        for node_with_score in nodes:
            node = node_with_score.node
            text = node.get_content() if hasattr(node, "get_content") else str(node)
            
            # Scan the content
            scan_result = self._scanner.scan(
                text,
                context={"location": f"retrieved_doc:{node.node_id if hasattr(node, 'node_id') else 'unknown'}"}
            )
            
            # Filter unsafe nodes if configured
            if self._filter_unsafe and not scan_result.is_safe:
                if scan_result.has_critical or scan_result.has_high:
                    self._filtered_count += 1
                    continue
            
            # Redact PII if configured
            if self._redact_pii and scan_result.findings:
                pii_findings = [
                    f for f in scan_result.findings
                    if f.threat_type == ThreatType.PII_EXPOSURE
                ]
                if pii_findings:
                    text = self._redact_content(text, pii_findings)
                    self._redacted_count += 1
                    
                    # Create new node with redacted content
                    if isinstance(node, TextNode):
                        node = TextNode(
                            text=text,
                            metadata=node.metadata,
                            id_=node.node_id if hasattr(node, "node_id") else None,
                        )
                        node_with_score = NodeWithScore(node=node, score=node_with_score.score)
            
            processed_nodes.append(node_with_score)
        
        return processed_nodes
    
    async def _aretrieve(self, query_bundle: QueryBundle) -> List[NodeWithScore]:
        """Async retrieve - delegates to sync for now."""
        return self._retrieve(query_bundle)
    
    def _redact_content(self, text: str, findings: List[SecurityFinding]) -> str:
        """
        Redact PII from text based on findings.
        
        Args:
            text: Original text
            findings: PII findings to redact
            
        Returns:
            Text with PII redacted
        """
        redacted = text
        
        # Redaction patterns by finding type
        patterns = {
            "email": (
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "[EMAIL REDACTED]"
            ),
            "phone_us": (
                r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                "[PHONE REDACTED]"
            ),
            "ssn": (
                r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
                "[SSN REDACTED]"
            ),
            "credit_card": (
                r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
                "[CARD REDACTED]"
            ),
        }
        
        for finding in findings:
            if finding.matched_pattern in patterns:
                pattern, replacement = patterns[finding.matched_pattern]
                redacted = re.sub(pattern, replacement, redacted)
        
        return redacted
    
    def get_stats(self) -> Dict[str, int]:
        """Get retriever statistics."""
        return {
            "retrieve_count": self._retrieve_count,
            "filtered_count": self._filtered_count,
            "redacted_count": self._redacted_count,
        }


def create_secure_retriever(
    retriever: BaseRetriever,
    scanner: Optional[BaseScanner] = None,
    filter_unsafe: bool = False,
    redact_pii: bool = False,
) -> SecureRetriever:
    """
    Convenience function to create a secure retriever.
    
    Args:
        retriever: Base retriever to wrap
        scanner: Security scanner
        filter_unsafe: Filter out unsafe documents
        redact_pii: Redact PII from retrieved content
        
    Returns:
        SecureRetriever instance
    """
    return SecureRetriever(
        retriever=retriever,
        scanner=scanner,
        filter_unsafe=filter_unsafe,
        redact_pii=redact_pii,
    )


def filter_secure_documents(
    nodes: List[NodeWithScore],
    scanner: Optional[BaseScanner] = None,
    min_severity: Severity = Severity.HIGH,
) -> List[NodeWithScore]:
    """
    Filter a list of documents, removing those with security concerns.
    
    Args:
        nodes: List of nodes to filter
        scanner: Security scanner
        min_severity: Minimum severity to filter out
        
    Returns:
        Filtered list of safe nodes
    """
    if scanner is None:
        scanner = LocalScanner()
    
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    threshold_idx = severity_order.index(min_severity)
    
    safe_nodes: List[NodeWithScore] = []
    
    for node_with_score in nodes:
        node = node_with_score.node
        text = node.get_content() if hasattr(node, "get_content") else str(node)
        
        result = scanner.scan(text)
        
        # Check if any finding meets threshold
        should_filter = False
        for finding in result.findings:
            finding_idx = severity_order.index(finding.severity)
            if finding_idx <= threshold_idx:
                should_filter = True
                break
        
        if not should_filter:
            safe_nodes.append(node_with_score)
    
    return safe_nodes
