from abc import ABC, abstractmethod
from app.core.graph import DependencyGraph

class BaseParser(ABC):
    """Abstract base class for dependency manifest & lockfile parsers."""

    @abstractmethod
    def can_parse(self, filename: str, content: str) -> bool:
        """Check if this parser handles the given file."""
        pass

    @abstractmethod
    def parse(self, content: str, filename: str = "") -> DependencyGraph:
        """Parse file content and return a resolved DependencyGraph."""
        pass

