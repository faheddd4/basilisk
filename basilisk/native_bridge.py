"""
Basilisk Native Bridge — Python ctypes bindings for C/Go shared libraries.

Provides Python wrappers around the compiled native extensions:
  - Token analyzer (C)   → fast token estimation, entropy, similarity
  - Encoder (C)          → base64, hex, ROT13, URL encoding
  - Fuzzer (Go)          → mutation operators, crossover, batch ops
  - Matcher (Go)         → Aho-Corasick multi-pattern matching, refusal detection

Falls back to pure Python implementations if native libraries aren't available.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("basilisk.native")

# Library search paths
_LIB_DIRS = [
    Path(__file__).parent / "native_libs",
    Path(__file__).parent.parent / "native" / "build",
    Path("/usr/local/lib"),
    Path("/usr/lib"),
]

_EXT = ".so"  # Linux default; .dylib for macOS


def _find_lib(name: str) -> Optional[ctypes.CDLL]:
    """Find and load a shared library by name."""
    for d in _LIB_DIRS:
        path = d / f"{name}{_EXT}"
        if path.exists():
            try:
                lib = ctypes.CDLL(str(path))
                logger.info(f"Loaded native library: {path}")
                return lib
            except OSError as e:
                logger.warning(f"Failed to load {path}: {e}")
    logger.info(f"Native library {name} not found — using Python fallback")
    return None


# ============================================================
# Token Analyzer (C)
# ============================================================

_tokens_lib = _find_lib("libbasilisk_tokens")

if _tokens_lib:
    _tokens_lib.basilisk_estimate_tokens.argtypes = [ctypes.c_char_p]
    _tokens_lib.basilisk_estimate_tokens.restype = ctypes.c_int

    _tokens_lib.basilisk_entropy.argtypes = [ctypes.c_char_p]
    _tokens_lib.basilisk_entropy.restype = ctypes.c_double

    _tokens_lib.basilisk_levenshtein.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    _tokens_lib.basilisk_levenshtein.restype = ctypes.c_int

    _tokens_lib.basilisk_similarity.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    _tokens_lib.basilisk_similarity.restype = ctypes.c_double

    _tokens_lib.basilisk_count_confusables.argtypes = [ctypes.c_char_p]
    _tokens_lib.basilisk_count_confusables.restype = ctypes.c_int

    _tokens_lib.basilisk_fast_search.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    _tokens_lib.basilisk_fast_search.restype = ctypes.c_int


def estimate_tokens(text: str) -> int:
    """Estimate BPE token count. Uses C library or Python fallback."""
    if _tokens_lib:
        return _tokens_lib.basilisk_estimate_tokens(text.encode("utf-8"))
    # Python fallback: rough estimation
    return int(len(text.split()) * 1.3)


def entropy(text: str) -> float:
    """Calculate Shannon entropy of text."""
    if _tokens_lib:
        return _tokens_lib.basilisk_entropy(text.encode("utf-8"))
    # Python fallback
    import math
    from collections import Counter
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def levenshtein(s1: str, s2: str) -> int:
    """Levenshtein edit distance."""
    if _tokens_lib:
        return _tokens_lib.basilisk_levenshtein(s1.encode("utf-8"), s2.encode("utf-8"))
    # Python fallback
    n, m = len(s1), len(s2)
    if n > m:
        s1, s2, n, m = s2, s1, m, n
    prev = list(range(n + 1))
    for j in range(1, m + 1):
        curr = [j] + [0] * n
        for i in range(1, n + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            curr[i] = min(prev[i] + 1, curr[i - 1] + 1, prev[i - 1] + cost)
        prev = curr
    return prev[n]


def similarity(s1: str, s2: str) -> float:
    """Normalized string similarity (0.0-1.0)."""
    if _tokens_lib:
        return _tokens_lib.basilisk_similarity(s1.encode("utf-8"), s2.encode("utf-8"))
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    return 1.0 - levenshtein(s1, s2) / max_len


def count_confusables(text: str) -> int:
    """Count Unicode confusable characters in text."""
    if _tokens_lib:
        return _tokens_lib.basilisk_count_confusables(text.encode("utf-8"))
    # Minimal Python fallback
    confusable_ranges = [(0x0400, 0x04FF), (0x0370, 0x03FF)]  # Cyrillic, Greek
    return sum(1 for c in text if any(start <= ord(c) <= end for start, end in confusable_ranges))


def fast_search(text: str, pattern: str) -> int:
    """Fast case-insensitive substring search. Returns position or -1."""
    if _tokens_lib:
        return _tokens_lib.basilisk_fast_search(text.encode("utf-8"), pattern.encode("utf-8"))
    pos = text.lower().find(pattern.lower())
    return pos


# ============================================================
# Encoder (C)
# ============================================================

_encoder_lib = _find_lib("libbasilisk_encoder")

if _encoder_lib:
    _encoder_lib.basilisk_base64_encode.argtypes = [ctypes.c_char_p, ctypes.c_int]
    _encoder_lib.basilisk_base64_encode.restype = ctypes.c_char_p

    _encoder_lib.basilisk_rot13.argtypes = [ctypes.c_char_p]
    _encoder_lib.basilisk_rot13.restype = ctypes.c_char_p

    _encoder_lib.basilisk_url_encode.argtypes = [ctypes.c_char_p]
    _encoder_lib.basilisk_url_encode.restype = ctypes.c_char_p

    _encoder_lib.basilisk_unicode_escape.argtypes = [ctypes.c_char_p]
    _encoder_lib.basilisk_unicode_escape.restype = ctypes.c_char_p

    _encoder_lib.basilisk_reverse.argtypes = [ctypes.c_char_p]
    _encoder_lib.basilisk_reverse.restype = ctypes.c_char_p

    _encoder_lib.basilisk_free.argtypes = [ctypes.c_void_p]
    _encoder_lib.basilisk_free.restype = None


def native_base64_encode(data: bytes) -> str:
    """Base64 encode using C library or Python fallback."""
    if _encoder_lib:
        result = _encoder_lib.basilisk_base64_encode(data, len(data))
        if result:
            s = result.decode("utf-8")
            return s
    import base64
    return base64.b64encode(data).decode()


def native_rot13(text: str) -> str:
    """ROT13 using C library or Python fallback."""
    if _encoder_lib:
        result = _encoder_lib.basilisk_rot13(text.encode("utf-8"))
        if result:
            return result.decode("utf-8")
    import codecs
    return codecs.encode(text, "rot_13")


def native_url_encode(text: str) -> str:
    """URL encode using C library or Python fallback."""
    if _encoder_lib:
        result = _encoder_lib.basilisk_url_encode(text.encode("utf-8"))
        if result:
            return result.decode("utf-8")
    from urllib.parse import quote
    return quote(text)


def native_reverse(text: str) -> str:
    """String reversal using C library or Python fallback."""
    if _encoder_lib:
        result = _encoder_lib.basilisk_reverse(text.encode("utf-8"))
        if result:
            return result.decode("utf-8")
    return text[::-1]


# ============================================================
# Fuzzer Engine (Go)
# ============================================================

_fuzzer_lib = _find_lib("libbasilisk_fuzzer")

if _fuzzer_lib:
    _fuzzer_lib.BasiliskMutate.argtypes = [ctypes.c_char_p, ctypes.c_int]
    _fuzzer_lib.BasiliskMutate.restype = ctypes.c_char_p

    _fuzzer_lib.BasiliskMutateRandom.argtypes = [ctypes.c_char_p]
    _fuzzer_lib.BasiliskMutateRandom.restype = ctypes.c_char_p

    _fuzzer_lib.BasiliskCrossover.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    _fuzzer_lib.BasiliskCrossover.restype = ctypes.c_char_p

    _fuzzer_lib.BasiliskHomoglyphTransform.argtypes = [ctypes.c_char_p, ctypes.c_double]
    _fuzzer_lib.BasiliskHomoglyphTransform.restype = ctypes.c_char_p

    _fuzzer_lib.BasiliskZeroWidthInject.argtypes = [ctypes.c_char_p]
    _fuzzer_lib.BasiliskZeroWidthInject.restype = ctypes.c_char_p

    _fuzzer_lib.BasiliskCountRunes.argtypes = [ctypes.c_char_p]
    _fuzzer_lib.BasiliskCountRunes.restype = ctypes.c_int

    _fuzzer_lib.BasiliskFreeString.argtypes = [ctypes.c_char_p]
    _fuzzer_lib.BasiliskFreeString.restype = None

    _fuzzer_lib.BasiliskGetMutationCount.restype = ctypes.c_int


def native_mutate(payload: str, mutation_type: int = -1) -> str:
    """Mutate a payload using the Go fuzzer engine."""
    if _fuzzer_lib:
        if mutation_type < 0:
            result = _fuzzer_lib.BasiliskMutateRandom(payload.encode("utf-8"))
        else:
            result = _fuzzer_lib.BasiliskMutate(payload.encode("utf-8"), mutation_type)
        if result:
            s = result.decode("utf-8")
            return s
    # Python fallback: return unmodified
    return payload


def native_crossover(parent1: str, parent2: str, strategy: int = 0) -> str:
    """Crossover two payloads using the Go engine."""
    if _fuzzer_lib:
        result = _fuzzer_lib.BasiliskCrossover(
            parent1.encode("utf-8"), parent2.encode("utf-8"), strategy
        )
        if result:
            return result.decode("utf-8")
    # Python fallback: simple split
    words1 = parent1.split()
    words2 = parent2.split()
    mid = len(words1) // 2
    return " ".join(words1[:mid] + words2[len(words2) // 2:])


def native_homoglyph(text: str, rate: float = 0.15) -> str:
    """Replace characters with Unicode homoglyphs."""
    if _fuzzer_lib:
        result = _fuzzer_lib.BasiliskHomoglyphTransform(text.encode("utf-8"), rate)
        if result:
            return result.decode("utf-8")
    return text


def native_zero_width(text: str) -> str:
    """Insert zero-width characters."""
    if _fuzzer_lib:
        result = _fuzzer_lib.BasiliskZeroWidthInject(text.encode("utf-8"))
        if result:
            return result.decode("utf-8")
    return text


def get_mutation_count() -> int:
    """Get the number of available mutation types."""
    if _fuzzer_lib:
        return _fuzzer_lib.BasiliskGetMutationCount()
    return 11  # Default count


# ============================================================
# Pattern Matcher (Go)
# ============================================================

_matcher_lib = _find_lib("libbasilisk_matcher")

if _matcher_lib:
    _matcher_lib.BasiliskDetectRefusal.argtypes = [ctypes.c_char_p]
    _matcher_lib.BasiliskDetectRefusal.restype = ctypes.c_double

    _matcher_lib.BasiliskDetectSensitiveData.argtypes = [ctypes.c_char_p]
    _matcher_lib.BasiliskDetectSensitiveData.restype = ctypes.c_char_p

    _matcher_lib.BasiliskMatcherCreate.restype = ctypes.c_int
    _matcher_lib.BasiliskMatcherAddPattern.argtypes = [ctypes.c_int, ctypes.c_char_p]
    _matcher_lib.BasiliskMatcherAddPattern.restype = ctypes.c_int
    _matcher_lib.BasiliskMatcherBuild.argtypes = [ctypes.c_int]
    _matcher_lib.BasiliskMatcherSearch.argtypes = [ctypes.c_int, ctypes.c_char_p]
    _matcher_lib.BasiliskMatcherSearch.restype = ctypes.c_char_p
    _matcher_lib.BasiliskMatcherDestroy.argtypes = [ctypes.c_int]

    _matcher_lib.BasiliskFreeStr.argtypes = [ctypes.c_char_p]
    _matcher_lib.BasiliskFreeStr.restype = None


def detect_refusal(text: str) -> float:
    """Detect if text is a safety refusal. Returns confidence 0.0-1.0."""
    if _matcher_lib:
        return _matcher_lib.BasiliskDetectRefusal(text.encode("utf-8"))
    # Python fallback
    indicators = [
        "i can't", "i cannot", "i won't", "as an ai", "content policy",
        "safety guidelines", "i must decline", "i'm unable", "i refuse",
    ]
    lower = text.lower()
    matches = sum(1 for i in indicators if i in lower)
    return min(matches * 0.2, 1.0)


def detect_sensitive_data(text: str) -> list[dict]:
    """Detect sensitive data patterns in text. Returns list of matches."""
    if _matcher_lib:
        result = _matcher_lib.BasiliskDetectSensitiveData(text.encode("utf-8"))
        if result:
            import json
            try:
                return json.loads(result.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return []
    return []


class NativeMatcher:
    """Managed Aho-Corasick pattern matcher backed by Go."""

    def __init__(self):
        self._id = None
        if _matcher_lib:
            self._id = _matcher_lib.BasiliskMatcherCreate()

    def add_pattern(self, pattern: str) -> int:
        if self._id is not None:
            return _matcher_lib.BasiliskMatcherAddPattern(self._id, pattern.encode("utf-8"))
        return -1

    def build(self):
        if self._id is not None:
            _matcher_lib.BasiliskMatcherBuild(self._id)

    def search(self, text: str) -> list[dict]:
        if self._id is not None:
            result = _matcher_lib.BasiliskMatcherSearch(self._id, text.encode("utf-8"))
            if result:
                import json
                try:
                    return json.loads(result.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return []
        return []

    def __del__(self):
        if self._id is not None and _matcher_lib:
            try:
                _matcher_lib.BasiliskMatcherDestroy(self._id)
            except Exception:
                pass


# ============================================================
# Status / capability check
# ============================================================

def native_status() -> dict[str, bool]:
    """Return which native libraries are loaded."""
    return {
        "tokens_c": _tokens_lib is not None,
        "encoder_c": _encoder_lib is not None,
        "fuzzer_go": _fuzzer_lib is not None,
        "matcher_go": _matcher_lib is not None,
    }
