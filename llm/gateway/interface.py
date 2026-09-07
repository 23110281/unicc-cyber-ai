"""
LLM Gateway Interface (Team 4 draft, pending Team 3 input)

This module defines the abstract interface for the model-agnostic LLM Gateway.
It ensures that the application layer can seamlessly switch between an on-premise
LLM (Ollama) and an API-based LLM (Gemini) without changing the workflow.

Features required by Team 4:
- structured (dict) returns
- error and timeout handling
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List

class LLMGatewayError(Exception):
    """Base exception for LLM Gateway failures."""
    pass

class LLMTimeoutError(LLMGatewayError):
    """Raised when the LLM provider times out."""
    pass

class LLMInterface(ABC):
    """
    Abstract interface for LLM operations.
    Team 3 will implement concrete classes for Ollama and Gemini.
    """

    @abstractmethod
    def summarize_report(self, text: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Summarize a long cybersecurity report.
        
        Args:
            text: The raw text of the report.
            config: Optional configuration (e.g., timeout, max_tokens).
            
        Returns:
            Dict containing:
                - "summary" (str): The concise summary.
                - "key_points" (List[str]): Bullet points.
                
        Raises:
            LLMTimeoutError: If the request exceeds the timeout.
            LLMGatewayError: For general generation errors.
        """
        pass

    @abstractmethod
    def extract_entities(self, text: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Extract cybersecurity entities (CVEs, IOCs, etc.).
        
        Args:
            text: The text to extract from.
            config: Optional configuration.
            
        Returns:
            Dict containing:
                - "cves" (List[str])
                - "iocs" (List[str])
                - "threat_actors" (List[str])
                - "malware" (List[str])
                
        Raises:
            LLMTimeoutError: If the request exceeds the timeout.
            LLMGatewayError: For general generation errors.
        """
        pass

    @abstractmethod
    def investigate_synthesis(
        self, 
        query: str, 
        retrieved_evidence: List[Dict[str, Any]], 
        config: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Synthesize retrieved evidence against an investigator query.
        
        Args:
            query: The investigator's question or the new threat observation.
            retrieved_evidence: List of historical matched evidence from Team 2.
            config: Optional configuration.
            
        Returns:
            Dict containing:
                - "assessment" (str): The evidence-grounded assessment.
                - "confidence" (str): e.g., 'High', 'Medium', 'Low'.
                - "cited_sources" (List[str]): IDs of evidence heavily relied upon.
                
        Raises:
            LLMTimeoutError: If the request exceeds the timeout.
            LLMGatewayError: For general generation errors.
        """
        pass
