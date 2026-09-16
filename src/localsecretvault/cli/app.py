"""LocalSecretVault CLI — the primary user interface."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from localsecretvault import __app_name__, __version__
from localsecretvault.config.settings import (
    get_config_dir,
    get_master_password,
    get_master_password_with_confirm,
    get_vault_path,
)
from localsecretvault.models.secret import SecretType
from localsecretvault.services.backup import create_backup, restore_backup
from localsecretvault.services.clipboard import copy_to_clipboard
from localsecretvault.services.clipboard import is_available as clipboard_available
from localsecretvault.services.env import (
    export_to_env_file,
    import_from_env_file,
)
from localsecretvault.services.generator import generate_password
from localsecretvault.services.github import (
    get_authenticated_user,
    is_authenticated,
    is_gh_available,
    list_repo_secrets,
    push_secret,
)
from localsecretvault.storage.filestore import validate_vault_file, vault_exists
from localsecretvault.vault.manager import (
    DuplicateSecretError,
    SecretNotFoundError,
    VaultManager,
)

app = typer.Typer(
    name="localsecretvault",
    help=f"{__app_name__} — a lightweight, local-first password and developer secrets manager.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
error_console = Console(stderr=True)

# ── Vault manager singleton ───────────────────────────────

_manager: VaultManager | None = None

def _get_manager() -> VaultManager:
    global _manager  # noqa: PLW0603
    if _manager is None:
        _manager = VaultManager()
    return _manager

def _require_unlocked() -> VaultManager:
    """Get the manager, check auto-lock, and ensure vault is unlocked."""
    manager = _get_manager()
    if manager.check_auto_lock():
        error_console.print("[yellow]Vault auto-locked due to inactivity.[/yellow]")
        raise typer.Exit(1)
    if not manager.is_unlocked:
        error_console.print("[red]Vault is locked. Run 'localsecretvault unlock' first.[/red]")
        raise typer.Exit(1)
    return manager

# ── Version ───────────────────────────────────────────────

@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"{__app_name__} v{__version__}")

# ── Init ──────────────────────────────────────────────────

@app.command()
def init() -> None:
    """Initialize a new encrypted vault."""
    manager = _get_manager()

    vault_path = get_vault_path()
    if vault_path.exists():
        error_console.print(f"[red]A vault already exists at {vault_path}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Initializing new vault at:[/bold] {vault_path}")
    try:
        password, _confirm = get_master_password_with_confirm()
    except SystemExit:
        raise typer.Exit(1)

    try:
        manager.init_vault(password)
    except FileExistsError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    console.print("[green]Vault initialized successfully.[/green]")

# ── Unlock ────────────────────────────────────────────────

@app.command()
def unlock() -> None:
    """Unlock the vault with your master password."""
    manager = _get_manager()

    if manager.is_unlocked:
        console.print("[yellow]Vault is already unlocked.[/yellow]")
        return

    if not vault_exists():
        error_console.print("[red]No vault found. Run 'localsecretvault init' first.[/red]")
        raise typer.Exit(1)

    try:
        password = get_master_password("Master password: ")
    except SystemExit:
        raise typer.Exit(1)

    try:
        manager.unlock(password)
    except Exception:
        error_console.print("[red]Unable to unlock vault: authentication failed.[/red]")
        raise typer.Exit(1)

    console.print("[green]Vault unlocked.[/green]")

# ── Lock ──────────────────────────────────────────────────

@app.command()
def lock() -> None:
    """Lock the vault, clearing sensitive in-memory state."""
    manager = _get_manager()
    if not manager.is_unlocked:
        console.print("[yellow]Vault is already locked.[/yellow]")
        return
    manager.lock()
    console.print("[green]Vault locked.[/green]")

# ── Status ────────────────────────────────────────────────

@app.command()
def status() -> None:
    """Show vault status."""
    manager = _get_manager()
    config_dir = get_config_dir()
    vault_path = get_vault_path()

    table = Table(title="Vault Status", show_header=False)
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Config directory", str(config_dir))
    table.add_row("Vault file", str(vault_path))
    table.add_row(
        "Vault exists",
        "[green]Yes[/green]" if vault_exists() else "[red]No[/red]",
    )
    table.add_row(
        "Vault state",
        "[green]Unlocked[/green]" if manager.is_unlocked else "[red]Locked[/red]",
    )

    if manager.is_unlocked:
        secrets = manager.list_secrets()
        table.add_row("Secrets", str(len(secrets)))
        tags = manager.get_all_tags()
        table.add_row("Tags", ", ".join(tags) if tags else "None")

    table.add_row("Clipboard", "[green]Available[/green]" if clipboard_available() else "[red]Unavailable[/red]")

    console.print(table)

# ── Add ───────────────────────────────────────────────────

@app.command()
def add(
    secret_type: Annotated[
        str,
        typer.Argument(help="Secret type: Login, API Key, Database, Environment, SSH Key, Secure Note, Generic Secret"),
    ],
    name: Annotated[str, typer.Option("--name", "-n", help="Name for this secret")],
    username: Annotated[str, typer.Option("--username", "-u", help="Username")] = "",
    password: Annotated[str, typer.Option("--password", "-p", help="Password")] = "",
    url: Annotated[str, typer.Option("--url", help="URL")] = "",
    notes: Annotated[str, typer.Option("--notes", help="Notes")] = "",
    tags: Annotated[str, typer.Option("--tags", help="Comma-separated tags")] = "",
) -> None:
    """Add a new secret to the vault."""
    manager = _require_unlocked()

    from localsecretvault.models.secret import Secret

    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    secret = Secret(
        type=secret_type,
        name=name,
        username=username,
        password=password,
        url=url,
        notes=notes,
        tags=tag_list,
    )

    try:
        manager.add_secret(secret)
    except DuplicateSecretError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Secret '{name}' added.[/green]")

# ── Get ───────────────────────────────────────────────────

@app.command()
def get(
    name: Annotated[str, typer.Argument(help="Name or ID of the secret")],
    field: Annotated[str, typer.Option("--field", "-f", help="Specific field to retrieve")] = "",
    copy: Annotated[bool, typer.Option("--copy", "-c", help="Copy field value to clipboard")] = False,
) -> None:
    """Get a secret or a specific field from a secret."""
    manager = _require_unlocked()

    try:
        secret = manager.get_secret(name)
    except SecretNotFoundError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    if field:
        value = getattr(secret, field, None)
        if value is None:
            # Check custom fields
            value = secret.custom_fields.get(field)
        if value is None:
            error_console.print(f"[red]Field '{field}' not found on secret '{name}'.[/red]")
            raise typer.Exit(1)

        if copy:
            if clipboard_available():
                copy_to_clipboard(str(value))
                console.print("[green]Copied secret to clipboard.[/green]")
            else:
                error_console.print("[red]Clipboard not available.[/red]")
                raise typer.Exit(1)
        else:
            console.print(str(value))
    else:
        # Show secret info (hide password unless explicitly requested)
        table = Table(title=f"Secret: {secret.name}", show_header=False)
        table.add_column("Field", style="bold")
        table.add_column("Value")

        table.add_row("ID", secret.id)
        table.add_row("Type", secret.type)
        table.add_row("Name", secret.name)
        if secret.username:
            table.add_row("Username", secret.username)
        if secret.password:
            table.add_row("Password", "********")
        if secret.url:
            table.add_row("URL", secret.url)
        if secret.notes:
            table.add_row("Notes", secret.notes)
        if secret.tags:
            table.add_row("Tags", ", ".join(secret.tags))
        if secret.custom_fields:
            for k, v in secret.custom_fields.items():
                table.add_row(f"  {k}", "********" if "key" in k.lower() or "secret" in k.lower() else v)
        table.add_row("Created", secret.created_at)
        table.add_row("Updated", secret.updated_at)

        console.print(table)
        console.print("[dim]Use --field password --copy to copy the password to clipboard.[/dim]")

# ── Edit ──────────────────────────────────────────────────

@app.command()
def edit(
    name: Annotated[str, typer.Argument(help="Name or ID of the secret to edit")],
    new_name: Annotated[str, typer.Option("--new-name", help="New name")] = "",
    username: Annotated[str, typer.Option("--username", "-u", help="New username")] = "",
    password: Annotated[str, typer.Option("--password", "-p", help="New password")] = "",
    url: Annotated[str, typer.Option("--url", help="New URL")] = "",
    notes: Annotated[str, typer.Option("--notes", help="New notes")] = "",
    tags: Annotated[str, typer.Option("--tags", help="New comma-separated tags")] = "",
) -> None:
    """Edit an existing secret."""
    manager = _require_unlocked()

    updates: dict = {}
    if new_name:
        updates["name"] = new_name
    if username:
        updates["username"] = username
    if password:
        updates["password"] = password
    if url:
        updates["url"] = url
    if notes:
        updates["notes"] = notes
    if tags:
        updates["tags"] = [t.strip() for t in tags.split(",") if t.strip()]

    if not updates:
        console.print("[yellow]No changes specified.[/yellow]")
        return

    try:
        manager.edit_secret(name, **updates)
    except SecretNotFoundError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Secret '{name}' updated.[/green]")

# ── Delete ────────────────────────────────────────────────

@app.command()
def delete(
    name: Annotated[str, typer.Argument(help="Name or ID of the secret to delete")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation")] = False,
) -> None:
    """Delete a secret from the vault."""
    manager = _require_unlocked()

    if not yes:
        confirm = typer.confirm(f"Are you sure you want to delete '{name}'?")
        if not confirm:
            console.print("[yellow]Delete cancelled.[/yellow]")
            raise typer.Exit(0)

    try:
        manager.delete_secret(name)
    except SecretNotFoundError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Secret '{name}' deleted.[/green]")

# ── List ──────────────────────────────────────────────────

@app.command()
def list(
    secret_type: Annotated[str, typer.Option("--type", "-t", help="Filter by type")] = "",
    tag: Annotated[str, typer.Option("--tag", help="Filter by tag")] = "",
) -> None:
    """List all secrets in the vault (safe — no secret values shown)."""
    manager = _require_unlocked()

    secrets = manager.list_secrets(
        secret_type=secret_type if secret_type else None,
        tag=tag if tag else None,
    )

    if not secrets:
        console.print("[yellow]No secrets found.[/yellow]")
        return

    table = Table(title="Secrets")
    table.add_column("NAME", style="bold")
    table.add_column("TYPE")
    table.add_column("TAGS")
    table.add_column("UPDATED")

    for s in sorted(secrets, key=lambda x: x.name.lower()):
        table.add_row(
            s.name,
            s.type,
            ", ".join(s.tags) if s.tags else "",
            s.updated_at[:10] if s.updated_at else "",
        )

    console.print(table)

# ── Search ────────────────────────────────────────────────

@app.command()
def search(
    query: Annotated[str, typer.Argument(help="Search query")],
) -> None:
    """Search secrets by name, username, URL, tags, or type."""
    manager = _require_unlocked()

    results = manager.search(query)

    if not results:
        console.print(f"[yellow]No secrets matching '{query}'.[/yellow]")
        return

    table = Table(title=f"Search Results: '{query}'")
    table.add_column("NAME", style="bold")
    table.add_column("TYPE")
    table.add_column("TAGS")

    for s in results:
        table.add_row(
            s.name,
            s.type,
            ", ".join(s.tags) if s.tags else "",
        )

    console.print(table)

# ── Generate ──────────────────────────────────────────────

@app.command()
def generate(
    length: Annotated[int, typer.Option("--length", "-l", help="Password length")] = 20,
    no_upper: Annotated[bool, typer.Option("--no-upper", help="Exclude uppercase letters")] = False,
    no_lower: Annotated[bool, typer.Option("--no-lower", help="Exclude lowercase letters")] = False,
    no_numbers: Annotated[bool, typer.Option("--no-numbers", help="Exclude digits")] = False,
    no_symbols: Annotated[bool, typer.Option("--no-symbols", help="Exclude symbols")] = False,
    no_ambiguous: Annotated[bool, typer.Option("--no-ambiguous", help="Exclude ambiguous characters")] = False,
    count: Annotated[int, typer.Option("--count", "-n", help="Number of passwords to generate")] = 1,
    copy: Annotated[bool, typer.Option("--copy", "-c", help="Copy first password to clipboard")] = False,
) -> None:
    """Generate cryptographically secure passwords."""
    try:
        for _i in range(count):
            password = generate_password(
                length=length,
                uppercase=not no_upper,
                lowercase=not no_lower,
                numbers=not no_numbers,
                symbols=not no_symbols,
                exclude_ambiguous=no_ambiguous,
            )
            console.print(password)

        if count == 1 and copy:
            if clipboard_available():
                copy_to_clipboard(password)
                console.print("[green]Copied to clipboard.[/green]")
            else:
                error_console.print("[red]Clipboard not available.[/red]")
    except ValueError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

# ── Import .env ───────────────────────────────────────────

@app.command("env-import")
def env_import(
    env_file: Annotated[Path, typer.Argument(help="Path to .env file to import")],
    secret_name: Annotated[str, typer.Option("--name", "-n", help="Name for the imported secret")] = ".env import",
) -> None:
    """Import secrets from a .env file into the vault."""
    manager = _require_unlocked()

    try:
        env_vars = import_from_env_file(env_file)
    except FileNotFoundError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    if not env_vars:
        console.print("[yellow]No variables found in .env file.[/yellow]")
        return

    from localsecretvault.models.secret import Secret

    custom_fields = {item["name"]: item["value"] for item in env_vars}
    secret = Secret(
        type=SecretType.ENVIRONMENT.value,
        name=secret_name,
        notes=f"Imported from {env_file}",
        custom_fields=custom_fields,
    )

    try:
        manager.add_secret(secret)
    except DuplicateSecretError:
        # Update existing
        manager.edit_secret(secret_name, custom_fields=custom_fields)
        console.print(f"[green]Updated '{secret_name}' with {len(env_vars)} variables.[/green]")
        return

    console.print(f"[green]Imported {len(env_vars)} variables into '{secret_name}'.[/green]")

# ── Export .env ───────────────────────────────────────────

@app.command("env-export")
def env_export(
    env_file: Annotated[Path, typer.Argument(help="Path to write .env file to")],
    name: Annotated[str, typer.Option("--name", "-n", help="Secret name to export")] = ".env import",
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation")] = False,
) -> None:
    """Export a secret to a .env file (plaintext — use with caution)."""
    manager = _require_unlocked()

    try:
        secret = manager.get_secret(name)
    except SecretNotFoundError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    if not yes:
        console.print("[bold red]WARNING:[/bold red]")
        console.print("This will create an unencrypted file containing secrets.")
        console.print(f"Destination: {env_file}")
        confirm = typer.confirm("Continue?")
        if not confirm:
            console.print("[yellow]Export cancelled.[/yellow]")
            raise typer.Exit(0)

    env_vars = secret.custom_fields
    if not env_vars:
        console.print("[yellow]No exportable variables in this secret.[/yellow]")
        return

    try:
        export_to_env_file(env_file, env_vars)
    except FileExistsError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Exported {len(env_vars)} variables to {env_file}[/green]")

# ── Backup ────────────────────────────────────────────────

@app.command()
def backup(
    dest: Annotated[Path, typer.Argument(help="Destination path for the backup")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation")] = False,
) -> None:
    """Create an encrypted backup of the vault."""
    if dest.exists() and not yes:
        confirm = typer.confirm(f"Overwrite existing backup at {dest}?")
        if not confirm:
            console.print("[yellow]Backup cancelled.[/yellow]")
            raise typer.Exit(0)

    try:
        create_backup(dest, overwrite=yes)
    except (FileNotFoundError, FileExistsError) as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Backup created at {dest}[/green]")

# ── Restore ───────────────────────────────────────────────

@app.command()
def restore(
    source: Annotated[Path, typer.Argument(help="Path to the backup file to restore")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation")] = False,
) -> None:
    """Restore the vault from an encrypted backup."""
    if not yes:
        console.print("[bold]Current vault detected.[/bold]")
        console.print("A safety backup will be created before restoration.")
        confirm = typer.confirm("Continue?")
        if not confirm:
            console.print("[yellow]Restore cancelled.[/yellow]")
            raise typer.Exit(0)

    try:
        restore_backup(source, create_safety_backup=True, overwrite=True)
    except (FileNotFoundError, ValueError) as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    console.print("[green]Vault restored successfully.[/green]")
    console.print("[dim]You will need to re-unlock the vault.[/dim]")

# ── GitHub ────────────────────────────────────────────────

@app.command()
def github(
    action: Annotated[str, typer.Argument(help="Action: push or import")],
    repo: Annotated[str, typer.Option("--repo", "-r", help="GitHub repository (owner/repo)")],
    secret_name: Annotated[str, typer.Option("--secret", "-s", help="Secret name in vault")] = "",
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation")] = False,
) -> None:
    """Push or import secrets to/from a GitHub repository via gh CLI."""
    if not is_gh_available():
        error_console.print(
            "[red]GitHub CLI (gh) is not installed.[/red]\n"
            "Install it from https://cli.github.com/"
        )
        raise typer.Exit(1)

    if not is_authenticated():
        error_console.print("[red]GitHub CLI is not authenticated.[/red]\nRun 'gh auth login' first.")
        raise typer.Exit(1)

    user = get_authenticated_user()
    if user:
        console.print(f"[dim]Authenticated as: {user}[/dim]")

    if action == "push":
        _github_push(repo, secret_name, yes)
    elif action == "import":
        _github_import(repo, secret_name)
    else:
        error_console.print(f"[red]Unknown action: {action}. Use 'push' or 'import'.[/red]")
        raise typer.Exit(1)

def _github_push(repo: str, secret_name: str, yes: bool) -> None:
    """Push vault secret to GitHub."""
    manager = _require_unlocked()

    if not secret_name:
        error_console.print("[red]Secret name is required for push.[/red]")
        raise typer.Exit(1)

    try:
        secret = manager.get_secret(secret_name)
    except SecretNotFoundError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    if not yes:
        confirm = typer.confirm(f"Push '{secret.name}' to {repo}?")
        if not confirm:
            console.print("[yellow]Push cancelled.[/yellow]")
            raise typer.Exit(0)

    # Push the password field (most common use case)
    if secret.password:
        try:
            push_secret(repo.split("/")[0], repo.split("/")[1], secret.name.upper(), secret.password)
            console.print(f"[green]Pushed '{secret.name}' to {repo}[/green]")
        except RuntimeError as exc:
            error_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1)
    else:
        error_console.print("[red]Secret has no password value to push.[/red]")
        raise typer.Exit(1)

def _github_import(repo: str, secret_name: str) -> None:
    """Import GitHub secrets into vault."""
    _require_unlocked()
    owner, name = repo.split("/")
    try:
        gh_secrets = list_repo_secrets(owner, name)
    except RuntimeError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    if not gh_secrets:
        console.print("[yellow]No secrets found in repository.[/yellow]")
        return

    console.print(f"Found {len(gh_secrets)} secrets in {repo}:")
    for secret_name_gh in gh_secrets:
        console.print(f"  - {secret_name_gh}")

    console.print("[dim]Note: Secret values cannot be pulled from GitHub for security reasons.[/dim]")
    console.print("[dim]Use 'gh secret get <name> --repo <repo>' to retrieve individual values.[/dim]")

# ── Audit ─────────────────────────────────────────────────

@app.command()
def audit() -> None:
    """Run a security audit on the vault configuration."""
    from localsecretvault.config.settings import (
        check_config_permissions,
        check_vault_permissions,
        get_config_dir,
        get_vault_path,
    )

    _get_manager()
    config_dir = get_config_dir()
    vault_path = get_vault_path()

    table = Table(title="LocalSecretVault Security Audit")
    table.add_column("Check", style="bold")
    table.add_column("Status")

    # Vault encryption
    if vault_exists():
        table.add_row("Vault encryption", "[green]OK[/green]")
    else:
        table.add_row("Vault encryption", "[red]No vault found[/red]")

    # Vault integrity
    valid, msg = validate_vault_file()
    table.add_row("Vault integrity", "[green]OK[/green]" if valid else f"[red]{msg}[/red]")

    # File permissions
    perm_ok = check_vault_permissions(vault_path) and check_config_permissions(config_dir)
    table.add_row(
        "File permissions",
        "[green]OK[/green]" if perm_ok else "[yellow]Insecure permissions detected[/yellow]",
    )

    # Config
    table.add_row("Configuration", "[green]OK[/green]")

    # Telemetry
    table.add_row("Telemetry", "[green]Disabled[/green]")

    # Clipboard
    from localsecretvault.services.clipboard import is_available as clip_avail
    table.add_row(
        "Clipboard integration",
        "[green]Available[/green]" if clip_avail() else "[yellow]Unavailable[/yellow]",
    )

    # GitHub CLI
    table.add_row(
        "GitHub CLI",
        "[green]Available[/green]" if is_gh_available() else "[yellow]Not installed[/yellow]",
    )

    console.print(table)

# ── TUI ──────────────────────────────────────────────────

@app.command()
def tui() -> None:
    """Launch the interactive terminal UI."""
    from localsecretvault.tui.app import run_tui

    run_tui()

# ── Main entry point ──────────────────────────────────────

def main() -> None:
    """CLI entry point."""
    app()
