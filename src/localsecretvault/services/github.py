"""GitHub integration via the gh CLI."""

from __future__ import annotations

import json
import shutil
import subprocess


def is_gh_available() -> bool:
    """Check if the gh CLI is installed."""
    return shutil.which("gh") is not None


def is_authenticated() -> bool:
    """Check if gh CLI is authenticated."""
    if not is_gh_available():
        return False
    try:
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def get_authenticated_user() -> str | None:
    """Get the authenticated GitHub username."""
    if not is_gh_available():
        return None
    try:
        result = subprocess.run(
            ["gh", "api", "user", "--jq", ".login"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def list_repo_secrets(owner: str, repo: str) -> dict[str, str]:
    """List secrets for a GitHub repository.

    Returns a dict of secret_name -> secret_value (empty for non-retrievable).
    Note: GitHub API does not expose secret values via listing.
    Only returns names and creation info.
    """
    if not is_gh_available():
        raise RuntimeError(
            "GitHub CLI (gh) is not installed.\n"
            "Install it from https://cli.github.com/"
        )

    try:
        result = subprocess.run(
            [
                "gh", "secret", "list",
                "--repo", f"{owner}/{repo}",
                "--json", "name,updatedAt",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to list secrets: {result.stderr.strip()}")

        data = json.loads(result.stdout)
        return {item["name"]: "" for item in data}
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise RuntimeError(f"GitHub CLI error: {exc}") from exc


def push_secret(
    owner: str,
    repo: str,
    secret_name: str,
    secret_value: str,
) -> None:
    """Push a single secret to a GitHub repository.

    Uses gh secret set which creates or updates.
    """
    if not is_gh_available():
        raise RuntimeError(
            "GitHub CLI (gh) is not installed.\n"
            "Install it from https://cli.github.com/"
        )

    try:
        result = subprocess.run(
            [
                "gh", "secret", "set", secret_name,
                "--repo", f"{owner}/{repo}",
                "--body", secret_value,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to set secret: {result.stderr.strip()}")
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise RuntimeError(f"GitHub CLI error: {exc}") from exc


def pull_secret(owner: str, repo: str, secret_name: str) -> str | None:
    """Pull a single secret value from a GitHub repository.

    Returns the secret value or None if not found.
    """
    if not is_gh_available():
        raise RuntimeError(
            "GitHub CLI (gh) is not installed.\n"
            "Install it from https://cli.github.com/"
        )

    try:
        result = subprocess.run(
            [
                "gh", "secret", "get", secret_name,
                "--repo", f"{owner}/{repo}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise RuntimeError(f"GitHub CLI error: {exc}") from exc
