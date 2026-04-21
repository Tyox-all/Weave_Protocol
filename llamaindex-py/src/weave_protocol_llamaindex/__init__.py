"""
Weave Protocol LlamaIndex Integration
=====================================

Security scanning and monitoring for LlamaIndex applications.

Quick Start:
    from weave_protocol_llamaindex import WeaveSecurityHandler
    from llama_index.core.callbacks import CallbackManager
    from llama_index.core import Settings
    
    # Create security handler
    handler = WeaveSecurityHandler()
    
    # Attach to LlamaIndex
    Settings.callback_manager = CallbackManager([handler])
    
    # Now all LlamaIndex operations are monitored!

For secure tools:
    from weave_protocol_llamaindex import SecureFunctionTool
    
    def my_function(query: str) -> str:
        return f"Result: {query}"
    
    tool = SecureFunctionTool.from_defaults(fn=my_function)

For secure retrievers:
    from weave_protocol_llamaindex import SecureRetriever
    
    secure_retriever = SecureRetriever(
        retriever=base_retriever,
        redact_pii=True
    )
"""

__version__ = "0.1.0"
__author__ = "Trent Yoxall"

# Core types
from .types import (
    ActionType,
    ApprovalCallback,
    RedactionCallback,
    ScanResult,
    SecurityConfig,
    SecurityEvent,
    SecurityFinding,
    Severity,
    ThreatType,
)

# Scanners
from .scanner import (
    BaseScanner,
    LocalScanner,
    PatternDefinition,
    RemoteScanner,
    create_scanner,
    DEFAULT_PATTERNS,
)

# Callback handler
from .callback import (
    WeaveSecurityHandler,
    SecurityBlockError,
    create_strict_handler,
    create_warning_handler,
    create_production_handler,
)

# Secure tools
from .secure_tool import (
    SecureFunctionTool,
    create_secure_tool,
    create_high_risk_tool,
)

# Secure retriever
from .secure_retriever import (
    SecureRetriever,
    create_secure_retriever,
    filter_secure_documents,
)

__all__ = [
    # Version
    "__version__",
    
    # Types
    "ActionType",
    "ApprovalCallback",
    "RedactionCallback",
    "ScanResult",
    "SecurityConfig",
    "SecurityEvent",
    "SecurityFinding",
    "Severity",
    "ThreatType",
    
    # Scanners
    "BaseScanner",
    "LocalScanner",
    "PatternDefinition",
    "RemoteScanner",
    "create_scanner",
    "DEFAULT_PATTERNS",
    
    # Callback handler
    "WeaveSecurityHandler",
    "SecurityBlockError",
    "create_strict_handler",
    "create_warning_handler",
    "create_production_handler",
    
    # Secure tools
    "SecureFunctionTool",
    "create_secure_tool",
    "create_high_risk_tool",
    
    # Secure retriever
    "SecureRetriever",
    "create_secure_retriever",
    "filter_secure_documents",
]
