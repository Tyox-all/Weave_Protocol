"""
Weave Protocol LlamaIndex - Secure Tool Wrappers
"""

from typing import Any, Callable, Dict, Optional, Union

from llama_index.core.tools import FunctionTool, ToolMetadata, ToolOutput
from llama_index.core.tools.types import BaseTool

from .callback import SecurityBlockError
from .scanner import BaseScanner, LocalScanner
from .types import ActionType, ApprovalCallback, SecurityConfig


class SecureFunctionTool(BaseTool):
    """
    A secure wrapper around LlamaIndex FunctionTool.
    
    Scans both inputs and outputs of tool calls for security threats.
    
    Usage:
        from weave_protocol_llamaindex import SecureFunctionTool
        
        def my_function(query: str) -> str:
            return f"Result for: {query}"
        
        tool = SecureFunctionTool.from_defaults(
            fn=my_function,
            name="my_tool",
            description="My secure tool"
        )
    """
    
    def __init__(
        self,
        fn: Callable[..., Any],
        metadata: ToolMetadata,
        scanner: Optional[BaseScanner] = None,
        config: Optional[SecurityConfig] = None,
        approval_callback: Optional[ApprovalCallback] = None,
    ):
        """
        Initialize the secure tool.
        
        Args:
            fn: The function to wrap
            metadata: Tool metadata (name, description, etc.)
            scanner: Security scanner to use
            config: Security configuration
            approval_callback: Optional callback for high-risk operations
        """
        self._fn = fn
        self._metadata = metadata
        self._scanner = scanner or LocalScanner()
        self._config = config or SecurityConfig()
        self._approval_callback = approval_callback
        
        # Stats
        self._call_count = 0
        self._blocked_count = 0
    
    @classmethod
    def from_defaults(
        cls,
        fn: Callable[..., Any],
        name: Optional[str] = None,
        description: Optional[str] = None,
        scanner: Optional[BaseScanner] = None,
        config: Optional[SecurityConfig] = None,
        approval_callback: Optional[ApprovalCallback] = None,
    ) -> "SecureFunctionTool":
        """
        Create a SecureFunctionTool from a function.
        
        Args:
            fn: Function to wrap
            name: Tool name (defaults to function name)
            description: Tool description (defaults to docstring)
            scanner: Security scanner
            config: Security config
            approval_callback: Approval callback for high-risk ops
            
        Returns:
            Configured SecureFunctionTool
        """
        # Get name from function if not provided
        tool_name = name or fn.__name__
        
        # Get description from docstring if not provided
        tool_description = description or fn.__doc__ or f"Tool: {tool_name}"
        
        metadata = ToolMetadata(
            name=tool_name,
            description=tool_description,
        )
        
        return cls(
            fn=fn,
            metadata=metadata,
            scanner=scanner,
            config=config,
            approval_callback=approval_callback,
        )
    
    @classmethod
    def from_tool(
        cls,
        tool: Union[FunctionTool, BaseTool],
        scanner: Optional[BaseScanner] = None,
        config: Optional[SecurityConfig] = None,
        approval_callback: Optional[ApprovalCallback] = None,
    ) -> "SecureFunctionTool":
        """
        Wrap an existing LlamaIndex tool with security scanning.
        
        Args:
            tool: Existing tool to wrap
            scanner: Security scanner
            config: Security config
            approval_callback: Approval callback
            
        Returns:
            Secure version of the tool
        """
        # Extract the underlying function
        if isinstance(tool, FunctionTool):
            fn = tool._fn
        else:
            # Wrap the tool's call method
            fn = tool.call
        
        return cls(
            fn=fn,
            metadata=tool.metadata,
            scanner=scanner,
            config=config,
            approval_callback=approval_callback,
        )
    
    @property
    def metadata(self) -> ToolMetadata:
        """Get tool metadata."""
        return self._metadata
    
    def __call__(self, *args: Any, **kwargs: Any) -> ToolOutput:
        """
        Call the tool (required by BaseTool abstract class).
        
        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Tool output
        """
        return self.call(*args, **kwargs)
    
    def call(self, *args: Any, **kwargs: Any) -> ToolOutput:
        """
        Call the tool with security scanning.
        
        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Tool output
            
        Raises:
            SecurityBlockError: If input/output contains blocked threats
        """
        self._call_count += 1
        input_result = None
        
        # Scan inputs
        if self._config.scan_tool_calls:
            input_content = self._serialize_args(args, kwargs)
            input_result = self._scanner.scan(
                input_content,
                context={"location": f"tool_input:{self._metadata.name}"}
            )
            
            if self._config.should_block(input_result):
                self._blocked_count += 1
                raise SecurityBlockError(
                    f"Tool input blocked: {input_result.findings[0].description}",
                    result=input_result,
                )
        
        # Check approval for high-risk operations
        if self._approval_callback:
            approved = self._approval_callback(
                self._metadata.name,
                str(args) + str(kwargs),
                {"args": args, "kwargs": kwargs}
            )
            if not approved:
                self._blocked_count += 1
                raise SecurityBlockError(
                    f"Tool call not approved: {self._metadata.name}",
                    result=input_result,
                )
        
        # Execute the function
        try:
            result = self._fn(*args, **kwargs)
        except Exception as e:
            return ToolOutput(
                content=f"Error: {str(e)}",
                tool_name=self._metadata.name,
                raw_input={"args": args, "kwargs": kwargs},
                raw_output=None,
                is_error=True,
            )
        
        # Scan output
        if self._config.scan_outputs:
            output_content = str(result) if result else ""
            output_result = self._scanner.scan(
                output_content,
                context={"location": f"tool_output:{self._metadata.name}"}
            )
            
            if self._config.should_block(output_result):
                self._blocked_count += 1
                raise SecurityBlockError(
                    f"Tool output blocked: {output_result.findings[0].description}",
                    result=output_result,
                )
        
        return ToolOutput(
            content=str(result),
            tool_name=self._metadata.name,
            raw_input={"args": args, "kwargs": kwargs},
            raw_output=result,
        )
    
    async def acall(self, *args: Any, **kwargs: Any) -> ToolOutput:
        """Async version of call."""
        # For now, delegate to sync version
        # TODO: Implement true async scanning
        return self.call(*args, **kwargs)
    
    def _serialize_args(self, args: tuple, kwargs: dict) -> str:
        """Serialize arguments for scanning."""
        parts = []
        for arg in args:
            parts.append(str(arg))
        for key, value in kwargs.items():
            parts.append(f"{key}={value}")
        return " ".join(parts)
    
    def get_stats(self) -> Dict[str, int]:
        """Get tool usage statistics."""
        return {
            "call_count": self._call_count,
            "blocked_count": self._blocked_count,
        }


def create_secure_tool(
    fn: Callable[..., Any],
    name: Optional[str] = None,
    description: Optional[str] = None,
    scanner: Optional[BaseScanner] = None,
    config: Optional[SecurityConfig] = None,
) -> SecureFunctionTool:
    """
    Convenience function to create a secure tool.
    
    Args:
        fn: Function to wrap
        name: Tool name
        description: Tool description
        scanner: Security scanner
        config: Security config
        
    Returns:
        SecureFunctionTool instance
    """
    return SecureFunctionTool.from_defaults(
        fn=fn,
        name=name,
        description=description,
        scanner=scanner,
        config=config,
    )


def create_high_risk_tool(
    fn: Callable[..., Any],
    approval_callback: ApprovalCallback,
    name: Optional[str] = None,
    description: Optional[str] = None,
    scanner: Optional[BaseScanner] = None,
) -> SecureFunctionTool:
    """
    Create a tool that requires approval before execution.
    
    Args:
        fn: Function to wrap
        approval_callback: Callback that returns True to approve
        name: Tool name
        description: Tool description
        scanner: Security scanner
        
    Returns:
        SecureFunctionTool with approval requirement
    """
    config = SecurityConfig(
        block_on_critical=True,
        block_on_high=True,
        block_on_medium=True,
        scan_tool_calls=True,
        scan_outputs=True,
    )
    
    return SecureFunctionTool.from_defaults(
        fn=fn,
        name=name,
        description=description,
        scanner=scanner,
        config=config,
        approval_callback=approval_callback,
    )
