"""Système central de présentation d'ARCHI MONITOR."""

import os
import sys
from enum import Enum


# ============================================================
# PALETTE DE COULEURS
# ============================================================

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GREY = "\033[90m"


def supports_color() -> bool:
    """Vérifie si le terminal peut afficher les couleurs."""
    return (
        "NO_COLOR" not in os.environ
        and os.environ.get("TERM", "").lower() != "dumb"
        and sys.stdout.isatty()
    )


COLOR_ENABLED = supports_color()


def colorize(text: str, color: str) -> str:
    """Applique une couleur uniquement si elle est disponible."""
    if not COLOR_ENABLED:
        return str(text)

    return f"{color}{text}{Colors.RESET}"


# ============================================================
# GESTION DES STATUTS
# ============================================================

STATUS_DISPLAY = {
    "passed": ("🟢", "RÉUSSI", Colors.GREEN),
    "failed": ("🔴", "ÉCHEC", Colors.RED),
    "error": ("🔴", "ERREUR", Colors.RED),
    "warning": ("🟡", "AVERTISSEMENT", Colors.YELLOW),
    "skipped": ("⚪", "IGNORÉ", Colors.GREY),
    "pending": ("🔵", "EN ATTENTE", Colors.BLUE),
}


def status_label(status, with_symbol: bool = True) -> str:
    """Retourne le libellé visuel d'un statut."""
    value = getattr(status, "value", status)
    key = str(value).strip().lower()

    symbol, label, color = STATUS_DISPLAY.get(
        key,
        ("⚪", "INCONNU", Colors.GREY),
    )

    message = f"{symbol} {label}" if with_symbol else label

    return colorize(message, color)


# ============================================================
# PROFILS DE PRÉSENTATION
# ============================================================

def is_expert(mode) -> bool:
    """Détermine si le profil actif est le profil Expert."""
    value = getattr(mode, "value", mode)
    return str(value).strip().lower() in {
        "2",
        "expert",
        "experte",
    }


def profile_text(mode, beginner_text: str, expert_text: str) -> str:
    """Sélectionne une formulation selon le profil actif."""
    return expert_text if is_expert(mode) else beginner_text


# ============================================================
# STRUCTURE VISUELLE
# ============================================================

def separator(
    character: str = "─",
    width: int = 64,
    color: str = Colors.GREY,
) -> None:
    """Affiche une ligne de séparation."""
    print(colorize(character * width, color))


def heading(title: str, subtitle: str | None = None) -> None:
    """Affiche un titre principal."""
    separator()
    print(colorize(title.upper(), Colors.CYAN + Colors.BOLD))

    if subtitle:
        print(colorize(subtitle, Colors.GREY))

    separator()


def section(title: str) -> None:
    """Affiche le titre d'une section."""
    print()
    print(colorize(f"── {title.upper()} ──", Colors.BLUE + Colors.BOLD))


def info(label: str, value) -> None:
    """Affiche une information sous forme de ligne."""
    print(f"{colorize(label, Colors.CYAN)} : {value}")


def message(text: str, color: str = Colors.WHITE) -> None:
    """Affiche un message avec une couleur facultative."""
    print(colorize(text, color))


# ============================================================
# IDENTITÉ VISUELLE — ARCHI DIGITAL
# ============================================================

def brand_logo() -> None:
    """Affiche l'identité visuelle centrée d'ARCHI DIGITAL."""

    try:
        width = os.get_terminal_size().columns
    except OSError:
        width = 56

    width = max(32, width)

    def centered(text):
        return text.center(width)

    print()

    logo = [
        ("             ●", Colors.CYAN + Colors.BOLD),
        ("            ╱ ╲", Colors.CYAN),
        ("           ╱   ╲", Colors.BLUE),
        ("          ●━━━━━●", Colors.CYAN + Colors.BOLD),
        ("         ╱       ╲", Colors.BLUE),
        ("        ●         ●", Colors.CYAN + Colors.BOLD),
    ]

    for artwork, color in logo:
        print(colorize(centered(artwork.strip()), color))

    print()

    print(colorize(
        centered("ARCHI DIGITAL"),
        Colors.WHITE + Colors.BOLD,
    ))

    print(colorize(
        centered("NETWORK • TECHNOLOGY • SECURITY"),
        Colors.CYAN,
    ))

    print()

    print(colorize(
        centered("ARCHI MONITOR"),
        Colors.WHITE + Colors.BOLD,
    ))

    print(colorize(
        centered("NETWORK INTELLIGENCE PLATFORM"),
        Colors.BLUE,
    ))

    print()
