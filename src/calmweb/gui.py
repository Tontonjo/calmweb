"""CalmWeb dashboard — a single CustomTkinter window driven from the tray.

The window is deliberately calm and legible: a fixed sidebar with the
protection switch always in reach, and five pages (status, activity,
settings, lists, about).  Everything user-facing goes through
:func:`calmweb.i18n.t`, so the whole interface can flip between French and
English without restarting.

The window lives in its own thread with its own ``mainloop``; the rest of
the application only ever calls :func:`show_dashboard`.
"""

from __future__ import annotations

import contextlib
import threading
import time
import webbrowser
from collections.abc import Callable
from typing import Any

import customtkinter as ctk

from . import __version__, config, stats
from .assets import app_icon, window_icon_path
from .config_io import (
    current_options,
    default_sources,
    get_custom_cfg_path,
    save_custom_cfg,
)
from .i18n import SUPPORTED, get_language, set_language, t
from .log import _LOG_LOCK, log, log_buffer
from .normalize import normalize_host, normalize_source_url, normalize_whitelist_entry

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------

GREEN = ("#1F9A63", "#2FB877")
GREEN_HOVER = ("#187A4E", "#279A63")
RED = ("#C0392B", "#E05B4C")
RED_HOVER = ("#9E2D22", "#C34739")
MUTED = ("#5C6672", "#9BA5B2")
CARD = ("#FFFFFF", "#22262C")
PAGE_BG = ("#F2F4F7", "#191C20")
SIDEBAR = ("#E7EAEF", "#15181C")
BORDER = ("#D7DCE3", "#2C3138")

BLOCK_COLOR = ("#B3261E", "#FF8A80")
ALLOW_COLOR = ("#1F7A4D", "#8BE0AF")
SYSTEM_COLOR = ("#4A5462", "#9BA5B2")

_PAGES = ("status", "activity", "settings", "lists", "about")

_window: Dashboard | None = None
_thread: threading.Thread | None = None
_lock = threading.RLock()


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


def _load_logo(size: int = 64) -> Any:
    """Return a CTkImage of the CalmWeb logo (calmweb.ico), or None.

    The 128-pixel frame is loaded and handed to CTkImage at the requested
    display size, so the logo stays sharp on high-DPI screens.
    """
    image = app_icon(active=False, size=128)
    if image is None:
        return None
    with contextlib.suppress(Exception):
        return ctk.CTkImage(light_image=image, dark_image=image, size=(size, size))
    return None


def _text_widget(widget: Any) -> Any:
    """Return the underlying ``tkinter.Text`` of a CTkTextbox."""
    return getattr(widget, "_textbox", widget)


# ---------------------------------------------------------------------------
# Backend bridges (imported lazily to avoid an import cycle with tray.py)
# ---------------------------------------------------------------------------


def _toggle_protection() -> None:
    from .tray import set_protection

    set_protection(not config.block_enabled)


def _reload_lists() -> None:
    from .tray import reload_config_action

    reload_config_action()


def _refresh_tray() -> None:
    with contextlib.suppress(Exception):
        from .tray import refresh_tray

        refresh_tray()


def _open_config_file() -> None:
    from .tray import open_config_in_editor

    threading.Thread(
        target=open_config_in_editor,
        args=(get_custom_cfg_path(config.INSTALL_DIR),),
        daemon=True,
    ).start()


# ---------------------------------------------------------------------------
# Small composable widgets
# ---------------------------------------------------------------------------


class StatCard(ctk.CTkFrame):
    """A large number with a caption underneath."""

    def __init__(self, master: Any, caption: str, color: Any = None) -> None:
        super().__init__(master, fg_color=CARD, corner_radius=14, border_width=1,
                         border_color=BORDER)
        self.value = ctk.CTkLabel(
            self,
            text="0",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=color or ("#1D2430", "#F2F4F7"),
        )
        self.value.pack(padx=18, pady=(16, 0), anchor="w")
        self.caption = ctk.CTkLabel(
            self, text=caption, font=ctk.CTkFont(size=12), text_color=MUTED
        )
        self.caption.pack(padx=18, pady=(0, 16), anchor="w")

    def set(self, value: str) -> None:
        with contextlib.suppress(Exception):
            self.value.configure(text=value)

    def set_caption(self, caption: str) -> None:
        with contextlib.suppress(Exception):
            self.caption.configure(text=caption)


class DetailRow(ctk.CTkFrame):
    """A ``label ............ value`` line."""

    def __init__(self, master: Any, label: str, value: str = "—") -> None:
        super().__init__(master, fg_color="transparent")
        self.grid_columnconfigure(1, weight=1)
        self.label = ctk.CTkLabel(self, text=label, font=ctk.CTkFont(size=13),
                                  text_color=MUTED, anchor="w")
        self.label.grid(row=0, column=0, sticky="w", pady=4)
        self.value = ctk.CTkLabel(self, text=value, font=ctk.CTkFont(size=13), anchor="e")
        self.value.grid(row=0, column=1, sticky="e", pady=4)

    def set(self, value: str) -> None:
        with contextlib.suppress(Exception):
            self.value.configure(text=value)


class SettingSwitch(ctk.CTkFrame):
    """A switch with a title and an explanatory second line."""

    def __init__(self, master: Any, title: str, help_text: str, value: bool,
                 command: Callable[[], None] | None = None) -> None:
        super().__init__(master, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)
        self.var = ctk.BooleanVar(value=bool(value))

        self.switch = ctk.CTkSwitch(
            self,
            text=title,
            variable=self.var,
            onvalue=True,
            offvalue=False,
            font=ctk.CTkFont(size=14, weight="bold"),
            progress_color=GREEN,
            command=command,
        )
        self.switch.grid(row=0, column=0, sticky="w")
        self.help = ctk.CTkLabel(
            self, text=help_text, font=ctk.CTkFont(size=12), text_color=MUTED,
            justify="left", anchor="w", wraplength=520,
        )
        self.help.grid(row=1, column=0, sticky="w", padx=(46, 0), pady=(2, 0))

    def get(self) -> bool:
        return bool(self.var.get())


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------


class Dashboard(ctk.CTk):
    """The CalmWeb control window."""

    def __init__(self, initial_page: str = "status") -> None:
        super().__init__()
        self._page = initial_page if initial_page in _PAGES else "status"
        self._after_id: str | None = None
        self._activity_revision = -1
        self._activity_query = ""
        self._activity_kind = "all"
        self._closing = False

        self.title(t("win.title"))
        self.geometry("960x640")
        self.minsize(860, 560)
        self.configure(fg_color=PAGE_BG)

        with contextlib.suppress(Exception):
            icon_path = window_icon_path()
            if icon_path:
                self.iconbitmap(icon_path)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._logo = _load_logo(56)
        self._build_sidebar()
        self._content = ctk.CTkFrame(self, fg_color="transparent")
        self._content.grid(row=0, column=1, sticky="nsew", padx=(0, 0), pady=0)
        self._content.grid_rowconfigure(0, weight=1)
        self._content.grid_columnconfigure(0, weight=1)
        self._page_footer: ctk.CTkFrame | None = None

        self._show_page(self._page)
        self.protocol("WM_DELETE_WINDOW", self.close)

        self.lift()
        self.attributes("-topmost", True)
        self.after(200, lambda: self.attributes("-topmost", False))
        self._tick()

    # -- sidebar -------------------------------------------------------

    def _build_sidebar(self) -> None:
        bar = ctk.CTkFrame(self, width=232, corner_radius=0, fg_color=SIDEBAR)
        bar.grid(row=0, column=0, sticky="nsw")
        bar.grid_propagate(False)
        bar.grid_rowconfigure(2, weight=1)
        self._sidebar = bar

        header = ctk.CTkFrame(bar, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(24, 18))
        if self._logo is not None:
            ctk.CTkLabel(header, image=self._logo, text="").pack()
        ctk.CTkLabel(
            header, text="Calm Web", font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=(10, 0))
        ctk.CTkLabel(
            header, text=f"v{__version__}", font=ctk.CTkFont(size=11), text_color=MUTED
        ).pack()

        nav = ctk.CTkFrame(bar, fg_color="transparent")
        nav.grid(row=1, column=0, sticky="ew", padx=14)
        self._nav_buttons: dict[str, ctk.CTkButton] = {}
        for page in _PAGES:
            button = ctk.CTkButton(
                nav,
                text=t(f"tab.{page}") if page != "status" else t("tab.status"),
                anchor="w",
                height=40,
                corner_radius=10,
                font=ctk.CTkFont(size=14),
                fg_color="transparent",
                text_color=("#1D2430", "#E6EAF0"),
                hover_color=("#D7DCE3", "#22262C"),
                command=lambda p=page: self._show_page(p),
            )
            button.pack(fill="x", pady=3)
            self._nav_buttons[page] = button

        footer = ctk.CTkFrame(bar, fg_color="transparent")
        footer.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 22))
        self._toggle_button = ctk.CTkButton(
            footer,
            text="",
            height=46,
            corner_radius=12,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._on_toggle,
        )
        self._toggle_button.pack(fill="x")

    # -- page routing --------------------------------------------------

    def _show_page(self, page: str) -> None:
        self._page = page if page in _PAGES else "status"
        for name, button in self._nav_buttons.items():
            selected = name == self._page
            with contextlib.suppress(Exception):
                button.configure(
                    fg_color=("#FFFFFF", "#22262C") if selected else "transparent",
                    font=ctk.CTkFont(size=14, weight="bold" if selected else "normal"),
                )
        for child in self._content.winfo_children():
            child.destroy()
        # A page's primary action lives in a pinned footer so it is never
        # hidden below the fold of a scrolling page.
        self._page_footer = ctk.CTkFrame(self._content, fg_color="transparent", height=1)
        self._page_footer.grid(row=1, column=0, sticky="ew", padx=26, pady=(0, 18))
        builder = {
            "status": self._page_status,
            "activity": self._page_activity,
            "settings": self._page_settings,
            "lists": self._page_lists,
            "about": self._page_about,
        }[self._page]
        frame = ctk.CTkScrollableFrame(self._content, fg_color="transparent")
        if self._page == "activity":
            frame = ctk.CTkFrame(self._content, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="nsew", padx=26, pady=(22, 12))
        frame.grid_columnconfigure(0, weight=1)
        builder(frame)
        # Pages without a primary action get their vertical space back.
        if not self._page_footer.winfo_children():
            self._page_footer.grid_remove()
        self._refresh()

    def _rebuild(self) -> None:
        """Rebuild every label after a language change."""
        with contextlib.suppress(Exception):
            self.title(t("win.title"))
        for page, button in self._nav_buttons.items():
            with contextlib.suppress(Exception):
                button.configure(text=t(f"tab.{page}"))
        self._show_page(self._page)

    # -- status page ---------------------------------------------------

    def _page_status(self, parent: ctk.CTkBaseClass) -> None:
        hero = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=16, border_width=1,
                            border_color=BORDER)
        hero.grid(row=0, column=0, sticky="ew")
        hero.grid_columnconfigure(1, weight=1)

        self._hero_dot = ctk.CTkLabel(hero, text="●", font=ctk.CTkFont(size=40))
        self._hero_dot.grid(row=0, column=0, rowspan=2, padx=(24, 16), pady=24)
        self._hero_title = ctk.CTkLabel(
            hero, text="", font=ctk.CTkFont(size=22, weight="bold"), anchor="w"
        )
        self._hero_title.grid(row=0, column=1, sticky="w", pady=(24, 0))
        self._hero_sub = ctk.CTkLabel(
            hero, text="", font=ctk.CTkFont(size=13), text_color=MUTED,
            anchor="w", justify="left", wraplength=520,
        )
        self._hero_sub.grid(row=1, column=1, sticky="w", pady=(2, 24), padx=(0, 20))

        cards = ctk.CTkFrame(parent, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", pady=(16, 0))
        for column in range(4):
            cards.grid_columnconfigure(column, weight=1, uniform="cards")

        self._card_blocked = StatCard(cards, t("status.card.blocked"), BLOCK_COLOR)
        self._card_allowed = StatCard(cards, t("status.card.allowed"), ALLOW_COLOR)
        self._card_domains = StatCard(cards, t("status.card.domains"))
        self._card_uptime = StatCard(cards, t("status.card.uptime"))
        for column, card in enumerate(
            (self._card_blocked, self._card_allowed, self._card_domains, self._card_uptime)
        ):
            card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 10, 0))

        details = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=16, border_width=1,
                               border_color=BORDER)
        details.grid(row=2, column=0, sticky="ew", pady=(16, 0))
        details.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            details, text=t("status.detail.title"), font=ctk.CTkFont(size=15, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="ew", padx=22, pady=(18, 6))

        self._rows: dict[str, DetailRow] = {}
        for index, key in enumerate(
            ("proxy", "lists", "whitelist", "lastreload", "connections", "http"),
            start=1,
        ):
            row = DetailRow(details, t(f"status.detail.{key}"))
            row.grid(row=index, column=0, sticky="ew", padx=22)
            self._rows[key] = row

        actions = ctk.CTkFrame(details, fg_color="transparent")
        actions.grid(row=9, column=0, sticky="ew", padx=22, pady=(14, 20))
        ctk.CTkButton(
            actions, text=t("status.refresh"), height=38, corner_radius=10,
            command=lambda: threading.Thread(target=_reload_lists, daemon=True).start(),
        ).pack(side="left")
        ctk.CTkButton(
            actions, text=t("tray.activity"), height=38, corner_radius=10,
            fg_color="transparent", border_width=1, border_color=BORDER,
            text_color=("#1D2430", "#E6EAF0"),
            hover_color=("#E7EAEF", "#22262C"),
            command=lambda: self._show_page("activity"),
        ).pack(side="left", padx=10)

    # -- activity page -------------------------------------------------

    def _page_activity(self, parent: ctk.CTkBaseClass) -> None:
        parent.grid_rowconfigure(1, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        bar.grid_columnconfigure(1, weight=1)

        self._activity_kind = "all"
        self._filter = ctk.CTkSegmentedButton(
            bar,
            values=[
                t("activity.filter.all"),
                t("activity.filter.blocked"),
                t("activity.filter.allowed"),
                t("activity.filter.system"),
            ],
            command=self._on_filter,
            font=ctk.CTkFont(size=13),
        )
        self._filter.set(t("activity.filter.all"))
        self._filter.grid(row=0, column=0, sticky="w")

        self._search = ctk.CTkEntry(
            bar, placeholder_text=t("activity.search"), height=32, corner_radius=8
        )
        self._search.grid(row=0, column=1, sticky="ew", padx=12)
        self._search.bind("<KeyRelease>", lambda _e: self._on_search())

        self._follow = ctk.CTkCheckBox(
            bar, text=t("activity.autoscroll"), font=ctk.CTkFont(size=12)
        )
        self._follow.select()
        self._follow.grid(row=0, column=2, padx=(0, 10))

        ctk.CTkButton(
            bar, text=t("common.export"), width=90, height=32, corner_radius=8,
            command=self._export_log,
        ).grid(row=0, column=3)

        self._activity_box = ctk.CTkTextbox(
            parent,
            wrap="none",
            corner_radius=14,
            border_width=1,
            border_color=BORDER,
            fg_color=CARD,
            font=ctk.CTkFont(family="Consolas", size=13),
        )
        self._activity_box.grid(row=1, column=0, sticky="nsew")

        raw = _text_widget(self._activity_box)
        with contextlib.suppress(Exception):
            mode = 1 if ctk.get_appearance_mode() == "Dark" else 0
            raw.tag_config("blocked", foreground=BLOCK_COLOR[mode])
            raw.tag_config("allowed", foreground=ALLOW_COLOR[mode])
            raw.tag_config("system", foreground=SYSTEM_COLOR[mode])
            raw.tag_config("time", foreground=SYSTEM_COLOR[mode])

        self._activity_status = ctk.CTkLabel(
            parent, text="", font=ctk.CTkFont(size=12), text_color=MUTED, anchor="w"
        )
        self._activity_status.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        self._activity_revision = -1

    def _on_filter(self, value: str) -> None:
        mapping = {
            t("activity.filter.all"): "all",
            t("activity.filter.blocked"): "blocked",
            t("activity.filter.allowed"): "allowed",
            t("activity.filter.system"): "system",
        }
        self._activity_kind = mapping.get(value, "all")
        self._activity_revision = -1
        self._refresh_activity()

    def _on_search(self) -> None:
        with contextlib.suppress(Exception):
            self._activity_query = self._search.get().strip().lower()
        self._activity_revision = -1
        self._refresh_activity()

    def _refresh_activity(self) -> None:
        if self._page != "activity":
            return
        revision = stats.revision()
        if revision == self._activity_revision:
            return
        self._activity_revision = revision

        kinds = None if self._activity_kind == "all" else (self._activity_kind,)
        events = stats.events(kinds=kinds, query=self._activity_query, limit=600)

        box = self._activity_box
        raw = _text_widget(box)
        try:
            at_bottom = box.yview()[1] >= 0.98
        except Exception:
            at_bottom = True

        box.configure(state="normal")
        box.delete("1.0", "end")

        if not events:
            box.insert("end", t("activity.empty"))
        else:
            reason_labels = {
                "blocklist": t("activity.reason.blocklist"),
                "manual": t("activity.reason.manual"),
                "whitelist": t("activity.reason.whitelist"),
                "http": t("activity.reason.http"),
                "port": t("activity.reason.port"),
                "ip": t("activity.reason.ip"),
                "invalid": t("activity.reason.invalid"),
                "revocation": t("activity.reason.revocation"),
            }
            for event in events:
                symbol = {"blocked": "✕", "allowed": "✓"}.get(event.kind, "•")
                host = event.host or event.detail
                if event.port and event.port not in (80, 443):
                    host = f"{host}:{event.port}"
                # Name the verb when it is not one of the everyday ones, so an
                # application using WebDAV or RPC-over-HTTP is recognisable.
                if event.proto and event.proto not in ("CONNECT", "GET", "POST"):
                    host = f"{event.proto} {host}"
                reason = reason_labels.get(event.reason, event.reason)
                suffix = f"  ({reason})" if reason else ""
                start = raw.index("end-1c")
                box.insert("end", f"{event.clock}  {symbol}  {host}{suffix}\n")
                with contextlib.suppress(Exception):
                    raw.tag_add(event.kind, start, raw.index("end-1c"))

        box.configure(state="disabled")
        if at_bottom or self._follow.get():
            with contextlib.suppress(Exception):
                box.see("end")
        with contextlib.suppress(Exception):
            self._activity_status.configure(text=t("activity.count", n=len(events)))

    def _export_log(self) -> None:
        try:
            from tkinter import filedialog

            target = filedialog.asksaveasfilename(
                parent=self,
                defaultextension=".txt",
                initialfile=time.strftime("calmweb-%Y%m%d-%H%M.txt"),
                filetypes=[("Texte", "*.txt")],
            )
            if not target:
                return
            with _LOG_LOCK:
                content = "\n".join(list(log_buffer))
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(content)
            log(f"{t('activity.export.done')} {target}")
        except Exception as e:
            log(f"Export error: {e}")

    # -- settings page -------------------------------------------------

    def _page_settings(self, parent: ctk.CTkBaseClass) -> None:
        rules = self._section(parent, t("settings.protection"), row=0)
        self._switches: dict[str, SettingSwitch] = {}
        for index, key in enumerate(
            (
                "block_http_traffic",
                "block_ip_direct",
                "block_http_other_ports",
                "notify_on_block",
            )
        ):
            switch = SettingSwitch(
                rules,
                t(f"settings.{key}"),
                t(f"settings.{key}.help"),
                bool(getattr(config, key, False)),
            )
            switch.grid(row=index + 1, column=0, sticky="ew", padx=22, pady=(6, 12))
            self._switches[key] = switch

        interface = self._section(parent, t("settings.interface"), row=1)
        language_row = ctk.CTkFrame(interface, fg_color="transparent")
        language_row.grid(row=1, column=0, sticky="ew", padx=22, pady=(6, 12))
        ctk.CTkLabel(language_row, text=t("settings.language"),
                     font=ctk.CTkFont(size=14)).pack(side="left")
        self._language = ctk.CTkSegmentedButton(
            language_row, values=["Français", "English"], command=self._on_language
        )
        self._language.set("Français" if get_language() == "fr" else "English")
        self._language.pack(side="left", padx=16)

        theme_row = ctk.CTkFrame(interface, fg_color="transparent")
        theme_row.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 16))
        ctk.CTkLabel(theme_row, text=t("settings.theme"),
                     font=ctk.CTkFont(size=14)).pack(side="left")
        self._theme_values = {
            t("settings.theme.system"): "system",
            t("settings.theme.light"): "light",
            t("settings.theme.dark"): "dark",
        }
        self._theme = ctk.CTkOptionMenu(
            theme_row, values=list(self._theme_values), command=self._on_theme, width=140
        )
        reverse = {v: k for k, v in self._theme_values.items()}
        self._theme.set(reverse.get(config.theme, t("settings.theme.system")))
        self._theme.pack(side="left", padx=16)

        advanced = self._section(parent, t("settings.advanced"), row=2)
        buttons = ctk.CTkFrame(advanced, fg_color="transparent")
        buttons.grid(row=1, column=0, sticky="ew", padx=22, pady=(6, 18))
        ctk.CTkButton(
            buttons, text=t("settings.openfile"), height=38, corner_radius=10,
            fg_color="transparent", border_width=1, border_color=BORDER,
            text_color=("#1D2430", "#E6EAF0"), hover_color=("#E7EAEF", "#22262C"),
            command=_open_config_file,
        ).pack(side="left")
        ctk.CTkButton(
            buttons, text=t("settings.reloadlists"), height=38, corner_radius=10,
            fg_color="transparent", border_width=1, border_color=BORDER,
            text_color=("#1D2430", "#E6EAF0"), hover_color=("#E7EAEF", "#22262C"),
            command=lambda: threading.Thread(target=_reload_lists, daemon=True).start(),
        ).pack(side="left", padx=10)

        footer = self._page_footer or parent
        ctk.CTkButton(
            footer, text=t("common.save"), height=42, width=180, corner_radius=10,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=GREEN, hover_color=GREEN_HOVER,
            command=self._save_settings,
        ).pack(side="left")
        self._settings_status = ctk.CTkLabel(
            footer, text="", font=ctk.CTkFont(size=12), text_color=MUTED,
            wraplength=560, justify="left",
        )
        self._settings_status.pack(side="left", padx=14)

    def _save_settings(self) -> None:
        try:
            for key, switch in self._switches.items():
                setattr(config, key, switch.get())
            config.language = get_language()
            save_custom_cfg(options=current_options())

            self._settings_status.configure(
                text=f"{t('settings.applied')}  {t('settings.restart_hint')}"
            )
            log("Paramètres enregistrés depuis l'interface.")
            _refresh_tray()
        except Exception as e:
            log(f"Save settings error: {e}")

    def _on_language(self, value: str) -> None:
        code = "fr" if value.lower().startswith("fr") else "en"
        if code not in SUPPORTED:
            code = "fr"
        set_language(code)
        config.language = code
        with contextlib.suppress(Exception):
            save_custom_cfg(options=current_options())
        _refresh_tray()
        self._rebuild()

    def _on_theme(self, value: str) -> None:
        theme = self._theme_values.get(value, "system")
        config.theme = theme
        with contextlib.suppress(Exception):
            ctk.set_appearance_mode({"system": "System", "light": "Light",
                                     "dark": "Dark"}[theme])
            save_custom_cfg(options=current_options())
        self._rebuild()

    # -- lists page ----------------------------------------------------

    def _page_lists(self, parent: ctk.CTkBaseClass) -> None:
        lookup = self._section(parent, t("lists.lookup.title"), row=0)
        row = ctk.CTkFrame(lookup, fg_color="transparent")
        row.grid(row=1, column=0, sticky="ew", padx=22, pady=(6, 6))
        row.grid_columnconfigure(0, weight=1)
        self._lookup_entry = ctk.CTkEntry(
            row, placeholder_text=t("lists.lookup.placeholder"), height=36, corner_radius=8
        )
        self._lookup_entry.grid(row=0, column=0, sticky="ew")
        self._lookup_entry.bind("<Return>", lambda _e: self._do_lookup())
        ctk.CTkButton(
            row, text=t("lists.lookup.button"), width=110, height=36, corner_radius=8,
            command=self._do_lookup,
        ).grid(row=0, column=1, padx=(10, 0))
        self._lookup_result = ctk.CTkLabel(
            lookup, text="", font=ctk.CTkFont(size=13, weight="bold"), anchor="w",
            justify="left", wraplength=620,
        )
        self._lookup_result.grid(row=2, column=0, sticky="ew", padx=22, pady=(2, 0))

        self._lookup_hint = ctk.CTkLabel(
            lookup, text="", font=ctk.CTkFont(size=12), text_color=MUTED, anchor="w",
            justify="left", wraplength=620,
        )
        self._lookup_hint.grid(row=3, column=0, sticky="ew", padx=22, pady=(4, 0))

        self._lookup_action = ctk.CTkButton(
            lookup, text="", height=36, width=200, corner_radius=8,
            fg_color=GREEN, hover_color=GREEN_HOVER, command=lambda: None,
        )
        self._lookup_action.grid(row=4, column=0, sticky="w", padx=22, pady=(10, 18))
        self._lookup_action.grid_remove()

        whitelist = self._section(parent, t("lists.whitelist.title"), row=1)
        ctk.CTkLabel(
            whitelist, text=t("lists.whitelist.help"), font=ctk.CTkFont(size=12),
            text_color=MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="ew", padx=22)
        self._whitelist_box = ctk.CTkTextbox(whitelist, height=118, corner_radius=10,
                                             border_width=1, border_color=BORDER)
        self._whitelist_box.grid(row=2, column=0, sticky="ew", padx=22, pady=(8, 16))
        self._whitelist_box.insert("1.0", "\n".join(sorted(config.whitelisted_domains)))

        blocklist = self._section(parent, t("lists.blocklist.title"), row=2)
        ctk.CTkLabel(
            blocklist, text=t("lists.blocklist.help"), font=ctk.CTkFont(size=12),
            text_color=MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="ew", padx=22)
        self._blocklist_box = ctk.CTkTextbox(blocklist, height=118, corner_radius=10,
                                             border_width=1, border_color=BORDER)
        self._blocklist_box.grid(row=2, column=0, sticky="ew", padx=22, pady=(8, 16))
        self._blocklist_box.insert("1.0", "\n".join(sorted(config.manual_blocked_domains)))

        sources = self._section(parent, t("lists.sources.title"), row=3)
        ctk.CTkLabel(
            sources, text=t("lists.sources.block.help"), font=ctk.CTkFont(size=12),
            text_color=MUTED, anchor="w", justify="left", wraplength=620,
        ).grid(row=1, column=0, sticky="ew", padx=22)
        self._block_sources_box = ctk.CTkTextbox(sources, height=118, corner_radius=10,
                                                 border_width=1, border_color=BORDER)
        self._block_sources_box.grid(row=2, column=0, sticky="ew", padx=22, pady=(8, 12))
        self._block_sources_box.insert("1.0", "\n".join(config.blocklist_source_urls))

        ctk.CTkLabel(
            sources, text=t("lists.sources.whitelist.help"), font=ctk.CTkFont(size=12),
            text_color=MUTED, anchor="w", justify="left", wraplength=620,
        ).grid(row=3, column=0, sticky="ew", padx=22)
        self._whitelist_sources_box = ctk.CTkTextbox(sources, height=76, corner_radius=10,
                                                     border_width=1, border_color=BORDER)
        self._whitelist_sources_box.grid(row=4, column=0, sticky="ew", padx=22, pady=(8, 12))
        self._whitelist_sources_box.insert("1.0", "\n".join(config.whitelist_source_urls))

        ctk.CTkButton(
            sources, text=t("lists.sources.reset"), height=36, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=BORDER,
            text_color=("#1D2430", "#E6EAF0"),
            hover_color=("#E7EAEF", "#22262C"),
            command=self._reset_sources,
        ).grid(row=5, column=0, sticky="w", padx=22, pady=(0, 16))

        footer = self._page_footer or parent
        ctk.CTkButton(
            footer, text=t("common.save"), height=42, width=180, corner_radius=10,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=GREEN, hover_color=GREEN_HOVER,
            command=self._save_lists,
        ).pack(side="left")
        self._lists_status = ctk.CTkLabel(
            footer, text="", font=ctk.CTkFont(size=12), text_color=MUTED,
            wraplength=520, justify="left",
        )
        self._lists_status.pack(side="left", padx=14)

    @staticmethod
    def _clean_domains(text: str, allow_networks: bool = False) -> set[str]:
        """Turn the contents of a list box into standard domains / IPs.

        Whatever the user pasted (a URL, ``||domain^``, ``0.0.0.0 domain``)
        is reduced to a bare host; unusable lines are dropped so the saved
        configuration only ever holds entries that can actually match.
        """
        out: set[str] = set()
        for line in (text or "").splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            if allow_networks:
                host, network = normalize_whitelist_entry(entry)
                if host:
                    out.add(host)
                elif network is not None:
                    out.add(str(network))
            else:
                host = normalize_host(entry)
                if host:
                    out.add(host)
        return out

    @staticmethod
    def _clean_sources(text: str) -> tuple[list[str], int]:
        """Turn a source box into an ordered, de-duplicated URL list.

        Returns ``(urls, dropped)``.  Order matters -- it is the download
        order -- so this keeps a list rather than a set, and reports how many
        lines were unusable instead of discarding them in silence.
        """
        urls: list[str] = []
        dropped = 0
        for line in (text or "").splitlines():
            entry = line.strip()
            if not entry:
                continue
            url = normalize_source_url(entry)
            if url is None:
                if not entry.startswith(("#", "!", ";")):
                    dropped += 1
                continue
            if url not in urls:
                urls.append(url)
        return urls, dropped

    def _reset_sources(self) -> None:
        """Put the built-in sources back in the boxes (saved on Save)."""
        try:
            block_sources, whitelist_sources = default_sources()
            self._block_sources_box.delete("1.0", "end")
            self._block_sources_box.insert("1.0", "\n".join(block_sources))
            self._whitelist_sources_box.delete("1.0", "end")
            self._whitelist_sources_box.insert("1.0", "\n".join(whitelist_sources))
            self._lists_status.configure(text="")
        except Exception as e:
            log(f"Reset sources error: {e}")

    def _save_lists(self) -> None:
        try:
            whitelist = self._clean_domains(self._whitelist_box.get("1.0", "end"), allow_networks=True)
            blocked = self._clean_domains(self._blocklist_box.get("1.0", "end"))
            block_sources, dropped_block = self._clean_sources(
                self._block_sources_box.get("1.0", "end")
            )
            whitelist_sources, dropped_white = self._clean_sources(
                self._whitelist_sources_box.get("1.0", "end")
            )
            with config._CONFIG_LOCK:
                config.whitelisted_domains = whitelist
                config.manual_blocked_domains = blocked
                config.blocklist_source_urls = block_sources
                config.whitelist_source_urls = whitelist_sources
            save_custom_cfg(
                blocked_set=blocked,
                whitelist_set=whitelist,
                options=current_options(),
                block_sources=block_sources,
                whitelist_sources=whitelist_sources,
            )

            dropped = dropped_block + dropped_white
            message = t("settings.applied")
            if dropped:
                message = f"{message}  {t('lists.sources.dropped', n=dropped)}"
            self._lists_status.configure(text=message)
            threading.Thread(target=_reload_lists, daemon=True).start()
        except Exception as e:
            log(f"Save lists error: {e}")

    @staticmethod
    def _clean_host(raw: str) -> str:
        """Turn whatever the user pasted into a bare hostname."""
        host = (raw or "").strip().lower()
        host = host.split("://", 1)[-1].split("/")[0].split("?")[0]
        return host.strip().strip(".").lstrip("*.")

    def _do_lookup(self, notice: str = "") -> None:
        """Show the verdict for the domain in the lookup box.

        *notice* is a confirmation line ("x is now allowed") kept above the
        explanation after an action.
        """
        try:
            host = self._clean_host(self._lookup_entry.get())
            if not host:
                return

            resolver = config.current_resolver
            if resolver is None or not hasattr(resolver, "describe"):
                self._lookup_result.configure(text=t("common.loading"))
                return

            verdict = resolver.describe(host)
            source = str(verdict["source"])
            blocked = bool(verdict["blocked"])
            match = str(verdict["match"])

            label = t(
                {
                    "whitelist": "lists.lookup.src.whitelist",
                    "manual": "lists.lookup.src.manual",
                    "downloaded": "lists.lookup.src.downloaded",
                    "ip": "lists.lookup.src.ip",
                    "none": "lists.lookup.src.none",
                }[source]
            )
            if match and match != host:
                label = f"{label}, {t('lists.lookup.src.parent', p=match)}"

            self._lookup_result.configure(
                text=t("lists.lookup.blocked" if blocked else "lists.lookup.allowed",
                       d=host, src=label),
                text_color=BLOCK_COLOR if blocked else ALLOW_COLOR,
            )

            # Explain what to do about it, and offer the one action that works.
            hint = ""
            if blocked and source in ("downloaded", "ip"):
                hint = t(f"lists.lookup.hint.{'ip' if source == 'ip' else 'downloaded'}")
                self._lookup_action.configure(
                    text=t("lists.lookup.allow"),
                    fg_color=GREEN,
                    hover_color=GREEN_HOVER,
                    command=lambda h=host: self._allow_domain(h),
                )
                self._lookup_action.grid()
            elif blocked and source == "manual":
                hint = t("lists.lookup.hint.manual")
                self._lookup_action.configure(
                    text=t("lists.lookup.remove_local"),
                    fg_color=GREEN,
                    hover_color=GREEN_HOVER,
                    command=lambda h=match or host: self._remove_local_block(h),
                )
                self._lookup_action.grid()
            else:
                self._lookup_action.grid_remove()

            self._lookup_hint.configure(
                text=f"{notice}\n{hint}".strip() if notice else hint
            )
        except Exception as e:
            log(f"Lookup error: {e}")

    def _set_box(self, box: Any, domains: set[str]) -> None:
        """Replace a list editor's contents with *domains*, one per line."""
        with contextlib.suppress(Exception):
            box.delete("1.0", "end")
            box.insert("1.0", "\n".join(sorted(domains)))

    def _allow_domain(self, host: str) -> None:
        """Whitelist *host*, apply it immediately, and persist it."""
        try:
            whitelist = self._clean_domains(self._whitelist_box.get("1.0", "end"), allow_networks=True)
            whitelist.add(host)
            blocked = self._clean_domains(self._blocklist_box.get("1.0", "end"))

            with config._CONFIG_LOCK:
                config.whitelisted_domains = whitelist
                config.manual_blocked_domains = blocked

            # Take effect on the next request instead of after the next download.
            with contextlib.suppress(Exception):
                if config.current_resolver is not None:
                    config.current_resolver.allow_now(host)

            self._set_box(self._whitelist_box, whitelist)
            save_custom_cfg(blocked_set=blocked, whitelist_set=whitelist,
                            options=current_options())
            self._do_lookup(notice=t("lists.lookup.allowed_now", d=host))
            threading.Thread(target=_reload_lists, daemon=True).start()
        except Exception as e:
            log(f"Allow domain error: {e}")

    def _remove_local_block(self, host: str) -> None:
        """Drop *host* from the user's own blocklist and persist it."""
        try:
            blocked = self._clean_domains(self._blocklist_box.get("1.0", "end"))
            blocked.discard(host)
            whitelist = self._clean_domains(self._whitelist_box.get("1.0", "end"), allow_networks=True)

            with config._CONFIG_LOCK:
                config.manual_blocked_domains = blocked
                config.whitelisted_domains = whitelist

            self._set_box(self._blocklist_box, blocked)
            save_custom_cfg(blocked_set=blocked, whitelist_set=whitelist,
                            options=current_options())
            self._do_lookup(notice=t("lists.lookup.removed_local", d=host))
            threading.Thread(target=_reload_lists, daemon=True).start()
        except Exception as e:
            log(f"Remove local block error: {e}")

    # -- about page ----------------------------------------------------

    def _page_about(self, parent: ctk.CTkBaseClass) -> None:
        card = self._section(parent, t("tab.about"), row=0)
        body = ctk.CTkFrame(card, fg_color="transparent")
        body.grid(row=1, column=0, sticky="ew", padx=22, pady=(6, 18))

        DetailRow(body, t("about.version"), __version__).pack(fill="x")
        DetailRow(body, t("status.detail.proxy"),
                  f"{config.PROXY_BIND_IP}:{config.PROXY_PORT}").pack(fill="x")
        DetailRow(body, t("about.configfile"),
                  get_custom_cfg_path(config.INSTALL_DIR)).pack(fill="x")

        buttons = ctk.CTkFrame(card, fg_color="transparent")
        buttons.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 18))
        self._update_button = ctk.CTkButton(
            buttons, text=t("about.check"), height=40, corner_radius=10,
            command=self._check_updates,
        )
        self._update_button.pack(side="left")
        ctk.CTkButton(
            buttons, text=t("about.project"), height=40, corner_radius=10,
            fg_color="transparent", border_width=1, border_color=BORDER,
            text_color=("#1D2430", "#E6EAF0"), hover_color=("#E7EAEF", "#22262C"),
            command=lambda: webbrowser.open(config.GITHUB_REPO_URL),
        ).pack(side="left", padx=10)

        ctk.CTkLabel(
            parent, text=t("about.disclaimer"), font=ctk.CTkFont(size=12),
            text_color=MUTED, wraplength=640, justify="left", anchor="w",
        ).grid(row=1, column=0, sticky="ew", pady=(14, 0))

    def _check_updates(self) -> None:
        from .tray import check_for_updates

        with contextlib.suppress(Exception):
            self._update_button.configure(text=t("about.checking"), state="disabled")

        def _done() -> None:
            with contextlib.suppress(Exception):
                self._update_button.configure(text=t("about.check"), state="normal")

        check_for_updates()
        self.after(4000, _done)

    # -- shared -------------------------------------------------------

    def _section(self, parent: ctk.CTkBaseClass, title: str, row: int) -> ctk.CTkFrame:
        card = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=16, border_width=1,
                            border_color=BORDER)
        card.grid(row=row, column=0, sticky="ew", pady=(0 if row == 0 else 16, 0))
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card, text=title, font=ctk.CTkFont(size=15, weight="bold"), anchor="w"
        ).grid(row=0, column=0, sticky="ew", padx=22, pady=(18, 2))
        return card

    def _on_toggle(self) -> None:
        threading.Thread(target=_toggle_protection, daemon=True).start()
        self.after(150, self._refresh)

    # -- periodic refresh ---------------------------------------------

    def _refresh(self) -> None:
        if self._closing:
            return
        snapshot = stats.snapshot()
        active = bool(config.block_enabled)
        starting = config.current_resolver is None

        with contextlib.suppress(Exception):
            self._toggle_button.configure(
                text=t("status.disable") if active else t("status.enable"),
                fg_color=RED if active else GREEN,
                hover_color=RED_HOVER if active else GREEN_HOVER,
            )

        if self._page != "status":
            if self._page == "activity":
                self._refresh_activity()
            return

        with contextlib.suppress(Exception):
            if starting:
                title, sub, color = t("status.starting"), t("status.sub.starting"), MUTED
            elif active:
                title, sub, color = t("status.protected"), t("status.sub.protected"), GREEN
            else:
                title, sub, color = (
                    t("status.unprotected"),
                    t("status.sub.unprotected"),
                    RED,
                )
            self._hero_dot.configure(text_color=color)
            self._hero_title.configure(text=title)
            self._hero_sub.configure(text=sub)

            self._card_blocked.set(f"{snapshot['blocked']:,}".replace(",", " "))
            self._card_allowed.set(f"{snapshot['allowed']:,}".replace(",", " "))
            self._card_uptime.set(stats.format_uptime(float(snapshot["uptime"])))

            counts = {}
            if config.current_resolver is not None and hasattr(config.current_resolver, "counts"):
                counts = config.current_resolver.counts()
            total = int(counts.get("blocked", 0)) + int(counts.get("manual", 0))
            self._card_domains.set(f"{total:,}".replace(",", " ") if total else "—")

            self._rows["proxy"].set(f"{config.PROXY_BIND_IP}:{config.PROXY_PORT}")
            self._rows["lists"].set(
                f"{int(counts.get('blocked', 0)):,}".replace(",", " ") if counts else
                t("common.loading")
            )
            self._rows["whitelist"].set(
                f"{int(counts.get('whitelist', 0))} + {int(counts.get('networks', 0))} CIDR"
                if counts else t("common.loading")
            )
            last = float(counts.get("last_reload", 0) or 0)
            self._rows["lastreload"].set(
                time.strftime("%H:%M:%S", time.localtime(last)) if last else t("common.never")
            )
            self._rows["connections"].set(str(snapshot["active"]))
            self._rows["http"].set(t("status.http.value"))

    def _tick(self) -> None:
        if self._closing:
            return
        with contextlib.suppress(Exception):
            self._refresh()
        with contextlib.suppress(Exception):
            self._after_id = self.after(1000, self._tick)

    # -- lifecycle -----------------------------------------------------

    def close(self) -> None:
        """Hide and destroy the window; CalmWeb keeps running in the tray."""
        global _window
        self._closing = True
        with contextlib.suppress(Exception):
            if self._after_id:
                self.after_cancel(self._after_id)
        with contextlib.suppress(Exception):
            self.quit()
        with contextlib.suppress(Exception):
            self.destroy()
        with _lock:
            _window = None


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def _run(page: str) -> None:
    """Create the window and run its event loop (called in a worker thread)."""
    global _window
    try:
        ctk.set_appearance_mode(
            {"system": "System", "light": "Light", "dark": "Dark"}.get(config.theme, "System")
        )
        ctk.set_default_color_theme("blue")
        window = Dashboard(page)
        with _lock:
            _window = window
        window.mainloop()
    except Exception as e:
        log(f"Dashboard error: {e}")
    finally:
        with _lock:
            _window = None


def show_dashboard(page: str = "status") -> None:
    """Open the dashboard, or bring the existing window to the front."""
    global _thread
    with _lock:
        window = _window

    if window is not None:
        def _raise() -> None:
            with contextlib.suppress(Exception):
                if window.state() == "iconic":
                    window.deiconify()
                window._show_page(page)
                window.lift()
                window.focus_force()

        with contextlib.suppress(Exception):
            window.after(0, _raise)
            return

    if _thread is not None and _thread.is_alive():
        return

    _thread = threading.Thread(target=_run, args=(page,), daemon=False)
    _thread.start()


def close_dashboard() -> None:
    """Close the dashboard if it is open (used on shutdown)."""
    with _lock:
        window = _window
    if window is not None:
        with contextlib.suppress(Exception):
            window.after(0, window.close)
