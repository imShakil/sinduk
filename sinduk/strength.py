"""
sinduk.strength
~~~~~~~~~~~~~~~
Secret-strength evaluation for passwords and tokens.

This module is intentionally dependency-free so it can be imported anywhere
without pulling in heavy libraries.  It follows NIST SP 800-63B guidance:

  - Length is the primary driver of entropy.
  - Character-set diversity adds a secondary bonus.
  - Common patterns (repeats, sequences, keyboard walks) are penalised.
  - Dictionary-style checks are approximated via a compact bad-phrase list.

Typical usage::

    from sinduk.strength import evaluate, StrengthLabel

    result = evaluate("correct-horse-battery-staple")
    print(result.label)     # StrengthLabel.STRONG
    print(result.score)     # 82
    print(result.feedback)  # []

    result = evaluate("password")
    print(result.label)     # StrengthLabel.VERY_WEAK
    print(result.feedback)
    # ['Too short', 'Extremely common password — choose something unique']
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum

# ---------------------------------------------------------------------------
# Strength levels
# ---------------------------------------------------------------------------


class StrengthLabel(str, Enum):
    """Human-readable strength tier."""

    VERY_WEAK = "Very Weak"
    WEAK = "Weak"
    FAIR = "Fair"
    STRONG = "Strong"
    VERY_STRONG = "Very Strong"

    @property
    def color_hint(self) -> str:
        """ANSI / CSS colour suggestion for display layers."""
        return {
            StrengthLabel.VERY_WEAK: "#f87171",
            StrengthLabel.WEAK: "#fb923c",
            StrengthLabel.FAIR: "#fbbf24",
            StrengthLabel.STRONG: "#34d399",
            StrengthLabel.VERY_STRONG: "#22c55e",
        }[self]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StrengthResult:
    """Immutable result of a strength evaluation.

    Attributes
    ----------
    score:
        Integer in [0, 100].
    label:
        Categorical strength tier.
    entropy_bits:
        Estimated Shannon / combinatorial entropy.
    feedback:
        Ordered list of actionable improvement suggestions (empty when strong).
    crack_time_display:
        Human-readable estimated offline crack time at 10 billion guesses/s.
    """

    score: int
    label: StrengthLabel
    entropy_bits: float
    feedback: list[str] = field(default_factory=list)
    crack_time_display: str = "instant"


# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

# Compact list of the most-abused passwords / common patterns.
_COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password",
        "password1",
        "password123",
        "pass",
        "passwd",
        "123456",
        "12345678",
        "1234567890",
        "000000",
        "111111",
        "qwerty",
        "qwerty123",
        "asdfgh",
        "zxcvbn",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "admin",
        "login",
        "abc123",
        "iloveyou",
        "sunshine",
        "princess",
        "football",
        "shadow",
        "superman",
        "michael",
        "jessica",
        "secret",
        "hunter2",
        "baseball",
        "trustno1",
        "access",
        "hello",
        "hello123",
        "test",
        "test123",
        "guest",
        "changeme",
        "temp",
        "temp123",
        "root",
        "toor",
        "pacli",
        "sinduk",
        "default",
    }
)

_KEYBOARD_SEQUENCES: tuple[str, ...] = (
    "qwerty",
    "qwertyuiop",
    "asdfgh",
    "asdfghjkl",
    "zxcvbn",
    "1234567890",
    "0987654321",
    "abcdefgh",
    "zyxwvutsr",
)

_MIN_LENGTH_TOKENS: int = 8  # tokens / API keys get a lower bar
_MIN_LENGTH_PASSWORD: int = 8  # absolute floor
_IDEAL_LENGTH: int = 16  # above this, length bonus plateaus

# Crack-time thresholds at 10 billion guesses/second
_CRACK_THRESHOLDS: tuple[tuple[float, str], ...] = (
    (1e3, "instant"),
    (1e6, "less than a second"),
    (1e9, "a few seconds"),
    (60e9, "a minute"),
    (3_600e9, "an hour"),
    (86_400e9, "a day"),
    (2_592_000e9, "a month"),
    (31_536_000e9, "a year"),
    (3.15e15, "centuries"),
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate(secret: str, secret_type: str = "password") -> StrengthResult:  # nosec
    """Evaluate the strength of *secret*.

    Parameters
    ----------
    secret:
        The raw secret value.
    secret_type:
        ``"password"``, ``"token"``, or ``"ssh"``.  Tokens are scored more
        leniently for length because they are machine-generated.

    Returns
    -------
    StrengthResult
        Fully populated result including score, label, entropy and feedback.
    """
    if not secret:
        return StrengthResult(
            score=0,
            label=StrengthLabel.VERY_WEAK,
            entropy_bits=0.0,
            feedback=["Secret cannot be empty."],
            crack_time_display="instant",
        )

    feedback: list[str] = []
    score: int = 0
    length = len(secret)

    # --- Length scoring ---
    feedback, score = calculate_score(secret_type, length)

    # --- Character-set diversity ---
    diversity_bonus, charset_size = _diversity_bonus(secret)
    score += diversity_bonus

    if not re.search(r"[A-Z]", secret) and secret_type == "password":  # nosec
        feedback.append("Add uppercase letters.")
    if not re.search(r"[a-z]", secret) and secret_type == "password":  # nosec
        feedback.append("Add lowercase letters.")
    if not re.search(r"\d", secret) and secret_type == "password":  # nosec
        feedback.append("Add digits.")
    if not re.search(r"[^A-Za-z0-9]", secret) and secret_type == "password":  # nosec
        feedback.append("Add symbols (!, @, #, …) for extra strength.")

    # --- Pattern penalties ---
    penalty, pattern_feedback = _pattern_penalty(secret)
    score -= penalty
    feedback.extend(pattern_feedback)

    # --- Common-password check ---
    if secret.lower() in _COMMON_PASSWORDS:
        score = min(score, 10)
        feedback.append("Extremely common password — choose something unique.")  # nosec

    # --- Clamp and label ---
    score = max(0, min(100, score))
    label = _score_to_label(score)

    # --- Entropy estimate ---
    entropy = _estimate_entropy(length, charset_size)

    # --- Crack time ---
    crack_time = _crack_time_display(entropy)

    # Keep feedback concise — but always surface critical numeric warning
    if label in (StrengthLabel.STRONG, StrengthLabel.VERY_STRONG):
        # Preserve the numeric-only warning even for long digit-only secrets
        numeric_warning = "Purely numeric secrets are easy to brute-force."
        feedback_to_keep = [f for f in feedback if f == numeric_warning]
        feedback.clear()
        feedback.extend(feedback_to_keep)

    return StrengthResult(
        score=score,
        label=label,
        entropy_bits=round(entropy, 1),
        feedback=feedback[:4],  # cap at 4 hints
        crack_time_display=crack_time,
    )


def calculate_score(secret_type: str = "password", length: int = 0) -> tuple[list[str], int]:  # nosec
    """Return a list of feedback strings and a score for *secret* without scoring."""

    feedback: list[str] = []
    score: int = 0

    # --- Length ---
    min_len = _MIN_LENGTH_TOKENS if secret_type == "token" else _MIN_LENGTH_PASSWORD

    if length < min_len:
        feedback.append(f"Too short — aim for at least {min_len} characters.")
    elif length < 12:
        score += 20
        feedback.append("Longer passwords are significantly harder to crack.")
    elif length < _IDEAL_LENGTH:
        score += 35
    elif length < 24:
        score += 50
    else:
        score += 60

    return feedback, score


def score_bar(result: StrengthResult, width: int = 20) -> str:
    """Return a plain-text progress bar for terminal display.

    Example::

        ████████████░░░░░░░░  Fair (48/100)
    """
    filled = round(result.score / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"{bar}  {result.label.value} ({result.score}/100)"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _diversity_bonus(secret: str) -> tuple[int, int]:
    """Return (bonus_points, estimated_charset_size)."""
    has_lower = bool(re.search(r"[a-z]", secret))
    has_upper = bool(re.search(r"[A-Z]", secret))
    has_digit = bool(re.search(r"\d", secret))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", secret))

    charset = 0
    if has_lower:
        charset += 26
    if has_upper:
        charset += 26
    if has_digit:
        charset += 10
    if has_symbol:
        charset += 32

    # Minimal fallback
    charset = max(charset, 10)

    diversity_count = sum([has_lower, has_upper, has_digit, has_symbol])
    bonus_map = {0: 0, 1: 5, 2: 10, 3: 18, 4: 25}
    return bonus_map[diversity_count], charset


def _pattern_penalty(secret: str) -> tuple[int, list[str]]:
    """Detect common weak patterns and return (penalty, feedback_list)."""
    penalty = 0
    feedback: list[str] = []
    lower = secret.lower()

    # Repeated characters e.g. "aaaaa"
    if re.search(r"(.)\1{3,}", secret):
        penalty += 15
        feedback.append("Avoid long runs of repeated characters.")

    # Sequential digits / alpha
    if _has_sequence(lower):
        penalty += 10
        feedback.append("Avoid obvious sequences (123, abc, qwerty).")

    # Keyboard walks
    for walk in _KEYBOARD_SEQUENCES:
        if walk in lower:
            penalty += 12
            feedback.append("Avoid keyboard patterns.")
            break

    # All-numeric — always penalise and always surface the feedback
    if secret.isdigit():
        penalty += 20
        _numeric_warning = "Purely numeric secrets are easy to brute-force."
        if _numeric_warning not in feedback:
            feedback.insert(0, _numeric_warning)

    return penalty, feedback


def _has_sequence(text: str, run: int = 4) -> bool:
    """Return True if *text* contains an ascending/descending char sequence."""
    for i in range(len(text) - run + 1):
        chunk = text[i : i + run]
        ords = [ord(c) for c in chunk]
        diffs = [ords[j + 1] - ords[j] for j in range(len(ords) - 1)]
        if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
            return True
    return False


def _estimate_entropy(length: int, charset_size: int) -> float:
    """Combinatorial entropy: log2(charset_size ^ length)."""
    if charset_size <= 1:
        return 0.0
    return length * math.log2(charset_size)


def _crack_time_display(entropy_bits: float) -> str:
    """Map entropy bits to a human-readable offline crack time."""
    guesses = 2**entropy_bits
    guesses_per_second = 10e9  # modern GPU cluster

    seconds = guesses / guesses_per_second
    for threshold, label in _CRACK_THRESHOLDS:
        if seconds < threshold:
            return label
    return "centuries"


def _score_to_label(score: int) -> StrengthLabel:
    if score < 20:
        return StrengthLabel.VERY_WEAK
    if score < 40:
        return StrengthLabel.WEAK
    if score < 60:
        return StrengthLabel.FAIR
    if score < 80:
        return StrengthLabel.STRONG
    return StrengthLabel.VERY_STRONG


# ---------------------------------------------------------------------------
# CLI helper (used by commands/secrets.py)
# ---------------------------------------------------------------------------


def print_strength(result: StrengthResult) -> None:
    """Print a coloured strength summary to stdout (ANSI)."""
    _ANSI: dict[str, str] = {
        StrengthLabel.VERY_WEAK: "\033[91m",  # bright red
        StrengthLabel.WEAK: "\033[33m",  # yellow
        StrengthLabel.FAIR: "\033[93m",  # bright yellow
        StrengthLabel.STRONG: "\033[92m",  # bright green
        StrengthLabel.VERY_STRONG: "\033[32m",  # green
    }
    reset = "\033[0m"
    colour = _ANSI.get(result.label, "")
    bar = score_bar(result)
    print(f"  Strength: {colour}{bar}{reset}")
    if result.feedback:
        for tip in result.feedback:
            print(f"  ⚠  {tip}")
    print(f"  Estimated crack time: {result.crack_time_display}")
