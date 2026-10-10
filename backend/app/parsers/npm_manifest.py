import json
import re
from typing import Dict, Any
from app.parsers.base import BaseParser
from app.core.graph import DependencyGraph
from app.core.models import ComponentNode, DependencyScope
from app.core.purl import to_purl

class NpmManifestParser(BaseParser):
    """
    Parser for package.json direct manifest files.
    Extracts direct runtime and development dependencies.
    """

    def can_parse(self, filename: str, content: str) -> bool:
        if filename.endswith("package.json"):
            return True
        try:
            data = json.loads(content)
            return ("dependencies" in data or "devDependencies" in data) and "packages" not in data and "lockfileVersion" not in data
        except Exception:
            return False

    def parse(self, content: str, filename: str = "package.json") -> DependencyGraph:
        try:
            data = json.loads(content)
        except Exception as e:
            raise ValueError(f"Invalid JSON in {filename}: {str(e)}")

        project_name = data.get("name", "npm-project")
        graph = DependencyGraph(project_name=project_name)

        prod_deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})

        for name, ver_str in prod_deps.items():
            clean_ver = self._clean_version(ver_str)
            purl = to_purl("npm", name, clean_ver)
            component = ComponentNode(
                purl=purl,
                ecosystem="npm",
                name=name,
                version=clean_ver,
                is_direct=True,
                scope=DependencyScope.RUNTIME,
                lockfile_path=f"dependencies.{name}"
            )
            graph.add_component(component)

        for name, ver_str in dev_deps.items():
            clean_ver = self._clean_version(ver_str)
            purl = to_purl("npm", name, clean_ver)
            if not graph.get_component(purl):
                component = ComponentNode(
                    purl=purl,
                    ecosystem="npm",
                    name=name,
                    version=clean_ver,
                    is_direct=True,
                    scope=DependencyScope.DEVELOPMENT,
                    lockfile_path=f"devDependencies.{name}"
                )
                graph.add_component(component)

        graph.compute_metrics()
        return graph

    def _clean_version(self, ver: str) -> str:
        """Strip npm semver range characters (^, ~, >=, =, v) to obtain base version."""
        cleaned = re.sub(r"^[v=^~><\s]+", "", str(ver).strip())
        return cleaned or "0.0.0"

