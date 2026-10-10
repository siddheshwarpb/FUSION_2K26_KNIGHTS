import re
from typing import Optional
from packaging.requirements import Requirement, InvalidRequirement
from app.parsers.base import BaseParser
from app.core.graph import DependencyGraph
from app.core.models import ComponentNode, DependencyScope
from app.core.purl import to_purl

class PythonReqsParser(BaseParser):
    """
    Parser for Python requirements.txt files.
    Extracts package names, pinned versions, markers, and records exact vs unpinned status.
    """

    def can_parse(self, filename: str, content: str) -> bool:
        if filename.endswith(".txt") or "requirements" in filename or filename.endswith(".in"):
            return True
        # Check if content has python-style packages
        for line in content.splitlines()[:10]:
            clean = line.strip()
            if clean and not clean.startswith("#"):
                if "==" in clean or ">=" in clean or "<=" in clean:
                    return True
        return False

    def parse(self, content: str, filename: str = "requirements.txt") -> DependencyGraph:
        graph = DependencyGraph(project_name="python-project")

        for line_num, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Strip inline comments
            if " #" in line:
                line = line.split(" #", 1)[0].strip()

            # Ignore flags like -r, -i, -f, -e
            if line.startswith("-") or line.startswith("--"):
                continue

            # Parse line using packaging.requirements.Requirement
            try:
                req = Requirement(line)
                name = req.name

                # Check pinned version
                exact_version: Optional[str] = None
                for spec in req.specifier:
                    if spec.operator == "==":
                        exact_version = spec.version
                        break

                if not exact_version:
                    # If not strictly pinned with ==, take the specifier or fallback
                    # Per readme1.md, manifest ranges are intent, but for OSV querying we note the constraint
                    specs = list(req.specifier)
                    if specs:
                        exact_version = specs[0].version
                    else:
                        # Unversioned requirement
                        exact_version = "latest"

                purl = to_purl("PyPI", name, exact_version)
                scope = DependencyScope.RUNTIME

                component = ComponentNode(
                    purl=purl,
                    ecosystem="PyPI",
                    name=name,
                    version=exact_version,
                    is_direct=True, # In requirements.txt, all items are direct declarations
                    scope=scope,
                    lockfile_path=f"{filename}:L{line_num}"
                )
                graph.add_component(component)

            except InvalidRequirement:
                # Fallback for simple regex pattern name==version
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.]+)", line)
                if match:
                    name, version = match.groups()
                    purl = to_purl("PyPI", name, version)
                    component = ComponentNode(
                        purl=purl,
                        ecosystem="PyPI",
                        name=name,
                        version=version,
                        is_direct=True,
                        scope=DependencyScope.RUNTIME,
                        lockfile_path=f"{filename}:L{line_num}"
                    )
                    graph.add_component(component)

        graph.compute_metrics()
        return graph

