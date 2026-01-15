"""
Security utilities for Active Defense Framework - STIG Compliant
Implements V-220631 (Input Validation) and V-220632 (Input Sanitization)

This module provides secure method dispatch and serialization to replace
unsafe eval() and pickle usage.
"""

import json
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class SafeMethodDispatch:
    """
    Safe method dispatch to replace eval('self.'+method) patterns.
    Implements STIG V-220631 by using whitelist validation for method names.
    """
    
    # Whitelist of allowed method name patterns (alphanumeric and underscore only)
    METHOD_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
    
    # Methods that should never be called via IPC (security-sensitive)
    BLOCKED_METHODS: Set[str] = {
        '__init__', '__del__', '__new__', '__class__',
        '__dict__', '__module__', '__weakref__',
        'exec', 'eval', 'compile', '__import__',
        '__getattribute__', '__setattr__', '__delattr__',
    }
    
    @staticmethod
    def validate_method_name(method: str) -> bool:
        """
        Validate that a method name is safe to dispatch.
        
        Args:
            method: Method name to validate
            
        Returns:
            True if method name is valid and safe, False otherwise
        """
        if not isinstance(method, str):
            return False
        
        # Check against blocked methods
        if method in SafeMethodDispatch.BLOCKED_METHODS:
            return False
        
        # Check pattern (alphanumeric and underscore only, must start with letter or underscore)
        if not SafeMethodDispatch.METHOD_PATTERN.match(method):
            return False
        
        # Don't allow double underscores (dunder methods)
        if method.startswith('__') and method.endswith('__'):
            return False
        
        return True
    
    @staticmethod
    def get_method(obj: Any, method: str) -> Optional[Callable]:
        """
        Safely get a method from an object using getattr with validation.
        
        Args:
            obj: Object to get method from
            method: Method name to retrieve
            
        Returns:
            Method callable if valid and exists, None otherwise
        """
        if not SafeMethodDispatch.validate_method_name(method):
            return None
        
        try:
            attr = getattr(obj, method, None)
            if attr is not None and callable(attr):
                return attr
        except (AttributeError, TypeError):
            pass
        
        return None
    
    @staticmethod
    def dispatch(obj: Any, method: str, *args, **kwargs) -> Any:
        """
        Safely dispatch a method call on an object.
        
        Args:
            obj: Object to call method on
            method: Method name to call
            *args: Positional arguments for method
            **kwargs: Keyword arguments for method
            
        Returns:
            Result of method call
            
        Raises:
            ValueError: If method name is invalid
            AttributeError: If method does not exist
        """
        if not SafeMethodDispatch.validate_method_name(method):
            raise ValueError(f"Invalid method name: {method}")
        
        func = getattr(obj, method, None)
        if func is None or not callable(func):
            raise AttributeError(f"Method not found: {method}")
        
        return func(*args, **kwargs)


class SecureEventSerializer:
    """
    Secure JSON-based serialization for events to replace pickle.
    Pickle is vulnerable to arbitrary code execution (STIG V-220631/V-220632).
    
    Note: This provides a JSON-based alternative for simple event data.
    Complex objects that require pickle should be carefully reviewed.
    """
    
    @staticmethod
    def serialize(data: Any) -> bytes:
        """
        Serialize data to JSON bytes.
        
        Args:
            data: Data to serialize (must be JSON-serializable)
            
        Returns:
            JSON-encoded bytes
        """
        return json.dumps(data, default=SecureEventSerializer._json_encoder).encode('utf-8')
    
    @staticmethod
    def deserialize(data: bytes) -> Any:
        """
        Deserialize JSON bytes to Python object.
        
        Args:
            data: JSON-encoded bytes
            
        Returns:
            Deserialized Python object
        """
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return json.loads(data)
    
    @staticmethod
    def _json_encoder(obj: Any) -> Any:
        """Custom JSON encoder for event objects."""
        if hasattr(obj, '__dict__'):
            # For objects, extract serializable attributes
            result = {'__class__': obj.__class__.__name__}
            for key, value in obj.__dict__.items():
                if not key.startswith('_'):
                    try:
                        json.dumps(value)
                        result[key] = value
                    except (TypeError, ValueError):
                        # Skip non-serializable attributes
                        if isinstance(value, (list, tuple)):
                            result[key] = list(value)
                        elif hasattr(value, '__name__'):
                            result[key] = value.__name__
            return result
        elif isinstance(obj, (set, frozenset)):
            return list(obj)
        elif isinstance(obj, bytes):
            return obj.decode('utf-8', errors='replace')
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class InputValidator:
    """
    Input validation utilities implementing STIG V-220631.
    Uses whitelist approach for all validations.
    """
    
    # Valid IP address pattern (IPv4)
    IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    
    # Valid hostname pattern
    HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """
        Validate IPv4 address format.
        
        Args:
            ip: IP address string to validate
            
        Returns:
            True if valid IPv4 address, False otherwise
        """
        if not isinstance(ip, str):
            return False
        if ip == 'localhost':
            return True
        return bool(InputValidator.IP_PATTERN.match(ip))
    
    @staticmethod
    def validate_port(port: Any) -> bool:
        """
        Validate port number.
        
        Args:
            port: Port number to validate
            
        Returns:
            True if valid port (1-65535), False otherwise
        """
        try:
            p = int(port)
            return 1 <= p <= 65535
        except (TypeError, ValueError):
            return False
    
    @staticmethod
    def validate_event_name(name: str) -> bool:
        """
        Validate event name format.
        
        Args:
            name: Event name to validate
            
        Returns:
            True if valid event name, False otherwise
        """
        if not isinstance(name, str):
            return False
        # Event names should be alphanumeric with underscores, max 255 chars
        if len(name) > 255:
            return False
        return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name))


class InputSanitizer:
    """
    Input sanitization utilities implementing STIG V-220632.
    Removes dangerous characters to prevent injection attacks.
    """
    
    # Characters to remove for security
    DANGEROUS_CHARS = re.compile(r'[<>"\';&|`$()]')
    
    @staticmethod
    def sanitize_string(user_input: str, max_length: int = 255) -> Optional[str]:
        """
        Sanitize a string by removing dangerous characters.
        
        Args:
            user_input: String to sanitize
            max_length: Maximum allowed length (default: 255)
            
        Returns:
            Sanitized string or None if input is invalid
        """
        if not isinstance(user_input, str):
            return None
        
        # Remove dangerous characters
        sanitized = InputSanitizer.DANGEROUS_CHARS.sub('', user_input.strip())
        
        # Enforce length limit
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized if sanitized else None
