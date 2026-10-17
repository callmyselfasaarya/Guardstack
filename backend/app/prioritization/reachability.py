import ast
import logging
import os
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any

logger = logging.getLogger("guardstack.prioritization.reachability")

class PythonCallGraphAnalyzer:
    def __init__(self, repo_dir: Path):
        self.repo_dir = repo_dir
        # Map: func_identifier -> list of called func_names
        self.call_graph: Dict[str, Set[str]] = defaultdict(set)
        # Map: func_name -> set of func_identifiers where it is defined
        self.func_definitions: Dict[str, Set[str]] = defaultdict(set)
        # Entrypoint function identifiers
        self.entrypoints: Set[str] = set()
        # Map: file_path -> list of (func_identifier, start_line, end_line)
        self.file_functions: Dict[str, List[Tuple[str, int, int]]] = defaultdict(list)
        # Built flag
        self._built = False

    def build_graph(self):
        """Parse all Python files in the repository and construct the call graph."""
        if self._built:
            return

        for root, dirs, files in os.walk(self.repo_dir):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tmp"}]
            for file in files:
                if file.endswith(".py"):
                    full_path = Path(root) / file
                    try:
                        rel_path = str(full_path.relative_to(self.repo_dir)).replace("\\", "/")
                        self._analyze_file(full_path, rel_path)
                    except Exception as e:
                        logger.debug(f"Could not parse AST for {full_path}: {e}")

        self._built = True
        logger.info(f"Built call graph: {len(self.call_graph)} nodes, {len(self.entrypoints)} entrypoints detected.")

    def _analyze_file(self, full_path: Path, rel_path: str):
        content = full_path.read_text(encoding="utf-8", errors="ignore")
        try:
            tree = ast.parse(content, filename=str(full_path))
        except SyntaxError:
            return

        visitor = _CallGraphVisitor(rel_path)
        visitor.visit(tree)

        for func_info in visitor.functions:
            func_id = f"{rel_path}:{func_info['name']}"
            self.file_functions[rel_path].append((func_id, func_info["start_line"], func_info["end_line"]))
            self.func_definitions[func_info["name"]].add(func_id)

            if func_info["is_entrypoint"]:
                self.entrypoints.add(func_id)

            for called in func_info["calls"]:
                self.call_graph[func_id].add(called)

    def analyze_finding_reachability(self, file_path: str, line_number: int) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Determines if a finding at (file_path, line_number) is reachable from any known entrypoint.
        Returns:
            status: 'reachable' | 'unreachable' | 'unknown'
            trace: dict detailing the call path from entrypoint to vulnerable function
        """
        if not file_path.endswith(".py"):
            return "unknown", None

        self.build_graph()
        norm_path = file_path.replace("\\", "/")

        # 1. Locate the containing function
        target_func_id = None
        funcs_in_file = self.file_functions.get(norm_path, [])
        for f_id, s_line, e_line in funcs_in_file:
            if s_line <= line_number <= e_line:
                target_func_id = f_id
                break

        # If outside any function (top-level module code)
        if not target_func_id:
            # Top-level code executed on import is often executed directly if imported by an entrypoint
            return "reachable", {
                "chain": [f"{norm_path}:<top-level-module-execution>"],
                "entrypoint": f"{norm_path}:<module>",
                "reachability_type": "top-level execution"
            }

        # If the target function is itself an entrypoint
        if target_func_id in self.entrypoints:
            return "reachable", {
                "chain": [f"{target_func_id} (Direct Route / Entrypoint)"],
                "entrypoint": target_func_id,
                "reachability_type": "direct entrypoint"
            }

        # 2. Search for path from any entrypoint to target_func_id using BFS
        target_name = target_func_id.split(":")[-1]

        for entry_id in self.entrypoints:
            path = self._find_bfs_path(entry_id, target_func_id, target_name)
            if path:
                return "reachable", {
                    "chain": path,
                    "entrypoint": entry_id,
                    "reachability_type": "call graph traversal"
                }

        # If no entrypoints were discovered at all in the project, treat as unknown
        if not self.entrypoints:
            return "unknown", {"reason": "No HTTP/CLI entrypoints identified in repository."}

        # Unreachable from any known route/entrypoint
        return "unreachable", {
            "reason": f"No call path connects entrypoints to '{target_func_id}'. Code appears to be dead or unused.",
            "containing_function": target_func_id
        }

    def _find_bfs_path(self, start_id: str, target_id: str, target_name: str) -> Optional[List[str]]:
        queue = deque([(start_id, [start_id])])
        visited = {start_id}

        while queue:
            curr_id, path = queue.popleft()
            if curr_id == target_id:
                return path

            # Check outbound calls
            for called_symbol in self.call_graph.get(curr_id, set()):
                if called_symbol == target_name:
                    return path + [target_id]

                # Resolve called_symbol to candidate full func identifiers
                candidate_ids = self.func_definitions.get(called_symbol, set())
                for cand in candidate_ids:
                    if cand not in visited:
                        visited.add(cand)
                        queue.append((cand, path + [cand]))

        return None


class _CallGraphVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str):
        self.rel_path = rel_path
        self.functions: List[Dict[str, Any]] = []
        self._current_function: Optional[Dict[str, Any]] = None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._process_func(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._process_func(node, is_async=True)

    def _process_func(self, node, is_async: bool):
        is_entry = False

        # Detect entrypoint decorators
        for decorator in node.decorator_list:
            dec_name = ""
            if isinstance(decorator, ast.Attribute):
                dec_name = decorator.attr
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute):
                    dec_name = decorator.func.attr
                elif isinstance(decorator.func, ast.Name):
                    dec_name = decorator.func.id

            if dec_name.lower() in {"get", "post", "put", "delete", "patch", "route", "websocket", "api_view"}:
                is_entry = True

        # Special function names
        if node.name in {"main", "handler", "lambda_handler", "app"}:
            is_entry = True

        func_data = {
            "name": node.name,
            "start_line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno + 20),
            "is_entrypoint": is_entry,
            "is_async": is_async,
            "calls": set()
        }

        prev_func = self._current_function
        self._current_function = func_data
        self.generic_visit(node)
        self.functions.append(func_data)
        self._current_function = prev_func

    def visit_Call(self, node: ast.Call):
        if self._current_function:
            callee = ""
            if isinstance(node.func, ast.Name):
                callee = node.func.id
            elif isinstance(node.func, ast.Attribute):
                callee = node.func.attr
            if callee:
                self._current_function["calls"].add(callee)
        self.generic_visit(node)