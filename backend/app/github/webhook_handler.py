import hashlib
import hmac
import logging
from typing import Dict, Any, Optional, Tuple
from app.config import settings

logger = logging.getLogger("guardstack.github.webhook")

class GitHubWebhookHandler:
    @staticmethod
    def verify_signature(payload_body: bytes, signature_header: Optional[str]) -> bool:
        """
        Verify GitHub webhook HMAC SHA256 signature (X-Hub-Signature-256).
        If secret is not set, allow requests (e.g. for development / simulation).
        """
        secret = settings.GITHUB_WEBHOOK_SECRET
        if not secret:
            return True

        if not signature_header or not signature_header.startswith("sha256="):
            return False

        expected_sig = signature_header.split("sha256=")[-1]
        computed_sig = hmac.new(
            secret.encode("utf-8"),
            payload_body,
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected_sig, computed_sig)

    @staticmethod
    def extract_event_metadata(event_type: str, payload: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Extract repository, commit, and PR metadata from a GitHub webhook event.
        Returns:
            trigger_action: 'scan_pr' | 'scan_push' | None
            metadata: dict of normalized parameters
        """
        repo_data = payload.get("repository", {})
        repo_full_name = repo_data.get("full_name")
        clone_url = repo_data.get("clone_url", "")
        default_branch = repo_data.get("default_branch", "main")

        if not repo_full_name:
            return None, {}

        if event_type == "pull_request":
            action = payload.get("action")
            if action in {"opened", "synchronize", "reopened"}:
                pr_data = payload.get("pull_request", {})
                return "scan_pr", {
                    "repo_full_name": repo_full_name,
                    "clone_url": clone_url,
                    "default_branch": default_branch,
                    "pr_number": pr_data.get("number"),
                    "pr_title": pr_data.get("title", ""),
                    "commit_hash": pr_data.get("head", {}).get("sha", "HEAD"),
                    "branch": pr_data.get("head", {}).get("ref", "feature-branch"),
                    "base_branch": pr_data.get("base", {}).get("ref", "main")
                }

        elif event_type == "push":
            ref = payload.get("ref", "")
            branch = ref.split("refs/heads/")[-1] if "refs/heads/" in ref else default_branch
            commit_hash = payload.get("after", "HEAD")
            # Skip delete branch pushes
            if commit_hash == "0000000000000000000000000000000000000000":
                return None, {}

            return "scan_push", {
                "repo_full_name": repo_full_name,
                "clone_url": clone_url,
                "default_branch": default_branch,
                "commit_hash": commit_hash,
                "branch": branch,
                "pr_number": None
            }

        return None, {}