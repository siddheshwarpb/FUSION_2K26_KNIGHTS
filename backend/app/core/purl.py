import urllib.parse
from typing import Tuple, Optional

def normalize_ecosystem(raw_ecosystem: str) -> str:
    """Normalize ecosystem name to canonical OSV / PURL ecosystem string."""
    eco = raw_ecosystem.strip().lower()
    if eco in ("npm", "javascript", "node"):
        return "npm"
    if eco in ("pypi", "python", "pip"):
        return "PyPI"
    if eco in ("maven", "java"):
        return "Maven"
    if eco in ("crates.io", "cargo", "rust"):
        return "crates.io"
    if eco in ("golang", "go"):
        return "Go"
    if eco in ("nuget", "c#", "dotnet"):
        return "NuGet"
    if eco in ("packagist", "composer", "php"):
        return "Packagist"
    if eco in ("rubygems", "gem", "ruby"):
        return "RubyGems"
    return raw_ecosystem

def to_purl(ecosystem: str, name: str, version: str) -> str:
    """
    Construct canonical Package URL (PURL).
    Handles scoped packages like @angular/core -> pkg:npm/%40angular/core@12.0.0
    """
    eco_type = normalize_ecosystem(ecosystem).lower()
    if eco_type == "pypi":
        # PyPI normalizes underscores to dashes or lowercase
        norm_name = name.strip().lower()
        return f"pkg:pypi/{norm_name}@{version}"
    elif eco_type == "npm":
        if name.startswith("@") and "/" in name:
            scope, pkg_name = name.split("/", 1)
            encoded_scope = urllib.parse.quote(scope)
            return f"pkg:npm/{encoded_scope}/{pkg_name}@{version}"
        else:
            return f"pkg:npm/{name}@{version}"
    elif eco_type == "maven":
        if ":" in name:
            group, artifact = name.split(":", 1)
            return f"pkg:maven/{group}/{artifact}@{version}"
        return f"pkg:maven/{name}@{version}"
    else:
        return f"pkg:{eco_type}/{name}@{version}"

def parse_purl(purl: str) -> Tuple[str, str, str]:
    """Parse a PURL back into (ecosystem, name, version)."""
    if not purl.startswith("pkg:"):
        raise ValueError(f"Invalid purl: {purl}")
    rest = purl[4:]
    parts = rest.split("/", 1)
    eco = parts[0]
    remainder = parts[1] if len(parts) > 1 else ""
    if "@" in remainder:
        name_part, version = remainder.rsplit("@", 1)
    else:
        name_part, version = remainder, ""

    # decode any %40 in scoped package
    name = urllib.parse.unquote(name_part)
    return normalize_ecosystem(eco), name, version

