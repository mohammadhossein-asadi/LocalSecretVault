"""Textual TUI for LocalSecretVault — interactive vault browser."""

from __future__ import annotations

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Select,
)

from localsecretvault.config.settings import get_vault_path
from localsecretvault.models.secret import SecretType
from localsecretvault.services.clipboard import copy_to_clipboard
from localsecretvault.services.clipboard import is_available as clipboard_available
from localsecretvault.services.generator import generate_password
from localsecretvault.vault.manager import (
    VaultManager,
)


class PasswordScreen(ModalScreen[str]):
    """Modal screen for entering the master password."""

    CSS = """
    PasswordScreen {
        align: center middle;
    }
    #dialog {
        width: 50;
        height: auto;
        border: thick $primary;
        padding: 1 2;
    }
    #dialog Label {
        margin-bottom: 1;
    }
    """

    def __init__(self, title: str = "Enter Master Password") -> None:
        super().__init__()
        self.title_text = title

    def compose(self) -> ComposeResult:
        with Container(id="dialog"):
            yield Label(self.title_text)
            yield Input(password=True, id="password", placeholder="Master password...")
            with Horizontal():
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel", variant="default")

    @on(Button.Pressed, "#ok")
    def on_ok(self) -> None:
        password = self.query_one("#password", Input).value
        if password:
            self.dismiss(password)

    @on(Button.Pressed, "#cancel")
    def on_cancel(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted)
    def on_submit(self, event: Input.Submitted) -> None:
        if event.input.id == "password" and event.input.value:
            self.dismiss(event.input.value)


class AddSecretScreen(ModalScreen[bool]):
    """Modal screen for adding a new secret."""

    CSS = """
    AddSecretScreen {
        align: center middle;
    }
    #add-dialog {
        width: 70;
        height: auto;
        max-height: 30;
        border: thick $primary;
        padding: 1 2;
        overflow: auto;
    }
    #add-dialog Label {
        margin-top: 1;
    }
    """

    def __init__(self, manager: VaultManager) -> None:
        super().__init__()
        self.manager = manager

    def compose(self) -> ComposeResult:
        with Container(id="add-dialog"):
            yield Label("Add New Secret", classes="title")
            yield Label("Name:")
            yield Input(id="name", placeholder="Secret name...")
            yield Label("Type:")
            yield Select(
                [(t.value, t.value) for t in SecretType],
                value=SecretType.LOGIN.value,
                id="type",
            )
            yield Label("Username:")
            yield Input(id="username", placeholder="Optional...")
            yield Label("Password:")
            yield Input(id="password", placeholder="Optional...", password=True)
            yield Label("URL:")
            yield Input(id="url", placeholder="Optional...")
            yield Label("Notes:")
            yield Input(id="notes", placeholder="Optional...")
            yield Label("Tags (comma-separated):")
            yield Input(id="tags", placeholder="e.g. dev,production...")
            with Horizontal():
                yield Button("Save", id="save", variant="primary")
                yield Button("Cancel", id="cancel", variant="default")

    @on(Button.Pressed, "#save")
    def on_save(self) -> None:
        name = self.query_one("#name", Input).value
        if not name:
            return
        from localsecretvault.models.secret import Secret
        tags_raw = self.query_one("#tags", Input).value
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []
        secret = Secret(
            type=self.query_one("#type", Select).value,
            name=name,
            username=self.query_one("#username", Input).value,
            password=self.query_one("#password", Input).value,
            url=self.query_one("#url", Input).value,
            notes=self.query_one("#notes", Input).value,
            tags=tags,
        )
        try:
            self.manager.add_secret(secret)
            self.dismiss(True)
        except Exception:
            self.dismiss(False)

    @on(Button.Pressed, "#cancel")
    def on_cancel(self) -> None:
        self.dismiss(False)


class SecretDetailScreen(ModalScreen[None]):
    """Modal screen showing secret details."""

    CSS = """
    SecretDetailScreen {
        align: center middle;
    }
    #detail-dialog {
        width: 60;
        height: auto;
        max-height: 25;
        border: thick $primary;
        padding: 1 2;
        overflow: auto;
    }
    """

    def __init__(self, secret_data: dict) -> None:
        super().__init__()
        self.secret_data = secret_data

    def compose(self) -> ComposeResult:
        with Container(id="detail-dialog"):
            yield Label(f"Secret: {self.secret_data.get('name', '')}", classes="title")
            yield Label(f"ID: {self.secret_data.get('id', '')}")
            yield Label(f"Type: {self.secret_data.get('type', '')}")
            if self.secret_data.get("username"):
                yield Label(f"Username: {self.secret_data['username']}")
            if self.secret_data.get("password"):
                yield Label("Password: ********")
            if self.secret_data.get("url"):
                yield Label(f"URL: {self.secret_data['url']}")
            if self.secret_data.get("notes"):
                yield Label(f"Notes: {self.secret_data['notes']}")
            if self.secret_data.get("tags"):
                yield Label(f"Tags: {', '.join(self.secret_data['tags'])}")
            yield Label(f"Created: {self.secret_data.get('created_at', '')}")
            yield Label(f"Updated: {self.secret_data.get('updated_at', '')}")
            with Horizontal():
                yield Button("Copy Password", id="copy-pw", variant="primary")
                yield Button("Close", id="close", variant="default")

    @on(Button.Pressed, "#copy-pw")
    def on_copy(self) -> None:
        pw = self.secret_data.get("password", "")
        if pw and clipboard_available():
            copy_to_clipboard(pw)
            self.notify("Password copied to clipboard.", severity="information")

    @on(Button.Pressed, "#close")
    def on_close(self) -> None:
        self.dismiss()


class VaultTUI(App):
    """Interactive terminal UI for LocalSecretVault."""

    TITLE = "LocalSecretVault"
    SUB_TITLE = "Local-first secrets manager"

    CSS = """
    Screen {
        layout: vertical;
    }
    #search-bar {
        height: 3;
        padding: 0 1;
    }
    #secret-table {
        height: 1fr;
    }
    #info-bar {
        height: 1;
        dock: bottom;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("l", "lock_vault", "Lock"),
        Binding("a", "add_secret", "Add"),
        Binding("r", "refresh", "Refresh"),
        Binding("s", "focus_search", "Search"),
        Binding("g", "generate_pw", "Generate"),
        Binding("enter", "view_secret", "View"),
        Binding("d", "delete_secret", "Delete"),
        Binding("c", "copy_password", "Copy Password"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.manager = VaultManager(get_vault_path())
        self.current_secrets: list[dict] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="search-bar"):
            yield Input(placeholder="Search secrets...", id="search-input")
            yield Select(
                [("All Types", "all")] + [(t.value, t.value) for t in SecretType],
                value="all",
                id="type-filter",
            )
        yield DataTable(id="secret-table")
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#secret-table", DataTable)
        table.add_columns("Name", "Type", "Tags", "Updated")
        table.cursor_type = "row"

        # Try to unlock
        if not self.manager.is_unlocked:
            await self._try_unlock()
        else:
            self._load_secrets()

    async def _try_unlock(self) -> None:
        result = await self.push_screen_wait(PasswordScreen("Unlock Vault"))
        if result is None:
            self.notify("No password entered. Exiting.", severity="warning")
            self.exit()
            return
        try:
            self.manager.unlock(result)
            self._load_secrets()
        except Exception:
            self.notify("Authentication failed.", severity="error")
            await self._try_unlock()

    def _load_secrets(self, filter_query: str = "", filter_type: str = "all") -> None:
        table = self.query_one("#secret-table", DataTable)
        table.clear()
        self.current_secrets = []

        try:
            if filter_query:
                secrets = self.manager.search(filter_query)
            else:
                secrets = self.manager.list_secrets(
                    secret_type=None if filter_type == "all" else filter_type,
                )
            for s in secrets:
                table.add_row(
                    s.name,
                    s.type,
                    ", ".join(s.tags) if s.tags else "",
                    s.updated_at[:10] if s.updated_at else "",
                )
                self.current_secrets.append(s.to_dict())
        except Exception:
            pass

    @on(Input.Changed, "#search-input")
    def on_search_changed(self, event: Input.Changed) -> None:
        filter_type = self.query_one("#type-filter", Select).value
        self._load_secrets(
            filter_query=event.value,
            filter_type=filter_type if filter_type != "all" else "all",
        )

    @on(Select.Changed, "#type-filter")
    def on_type_changed(self, event: Select.Changed) -> None:
        search_val = self.query_one("#search-input", Input).value
        self._load_secrets(
            filter_query=search_val,
            filter_type=event.value if event.value != "all" else "all",
        )

    def action_focus_search(self) -> None:
        self.query_one("#search-input", Input).focus()

    def action_refresh(self) -> None:
        search_val = self.query_one("#search-input", Input).value
        filter_type = self.query_one("#type-filter", Select).value
        self._load_secrets(
            filter_query=search_val,
            filter_type=filter_type if filter_type != "all" else "all",
        )

    def action_lock_vault(self) -> None:
        self.manager.lock()
        self.notify("Vault locked.", severity="information")

    async def action_add_secret(self) -> None:
        result = await self.push_screen_wait(AddSecretScreen(self.manager))
        if result:
            self._load_secrets()
            self.notify("Secret added.", severity="information")
        else:
            self.notify("Add cancelled.", severity="warning")

    def action_view_secret(self) -> None:
        table = self.query_one("#secret-table", DataTable)
        if table.cursor_row is not None and table.cursor_row < len(self.current_secrets):
            secret_data = self.current_secrets[table.cursor_row]
            self.push_screen(SecretDetailScreen(secret_data))

    def action_copy_password(self) -> None:
        table = self.query_one("#secret-table", DataTable)
        if table.cursor_row is not None and table.cursor_row < len(self.current_secrets):
            pw = self.current_secrets[table.cursor_row].get("password", "")
            if pw and clipboard_available():
                copy_to_clipboard(pw)
                self.notify("Password copied to clipboard.", severity="information")
            elif not pw:
                self.notify("No password to copy.", severity="warning")
            else:
                self.notify("Clipboard not available.", severity="error")

    def action_delete_secret(self) -> None:
        table = self.query_one("#secret-table", DataTable)
        if table.cursor_row is not None and table.cursor_row < len(self.current_secrets):
            name = self.current_secrets[table.cursor_row].get("name", "")
            try:
                self.manager.delete_secret(name)
                self._load_secrets()
                self.notify(f"Deleted '{name}'.", severity="information")
            except Exception as exc:
                self.notify(str(exc), severity="error")

    def action_generate_pw(self) -> None:
        pw = generate_password(length=24)
        if clipboard_available():
            copy_to_clipboard(pw)
            self.notify(f"Generated and copied: {pw[:4]}...{pw[-4:]}", severity="information")
        else:
            self.notify(f"Generated: {pw}", severity="information")


def run_tui() -> None:
    """Launch the TUI application."""
    app = VaultTUI()
    app.run()
