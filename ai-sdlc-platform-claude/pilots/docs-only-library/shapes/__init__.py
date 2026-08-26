"""Tiny geometry helpers used by the documentation pilot."""

from __future__ import annotations

import math

__all__ = ["area", "perimeter"]


def area(shape: str, **dims: float) -> float:
    """Area of ``shape`` (``"circle"``: ``r``; ``"rectangle"``: ``w``, ``h``).

    >>> round(area("circle", r=1.0), 3)
    3.142
    >>> area("rectangle", w=2.0, h=3.0)
    6.0
    """
    if shape == "circle":
        return math.pi * dims["r"] ** 2
    if shape == "rectangle":
        return dims["w"] * dims["h"]
    raise ValueError(f"unknown shape {shape!r}")


def perimeter(shape: str, **dims: float) -> float:
    """Perimeter of ``shape`` (same keyword arguments as :func:`area`).

    >>> perimeter("rectangle", w=2.0, h=3.0)
    10.0
    """
    if shape == "circle":
        return 2 * math.pi * dims["r"]
    if shape == "rectangle":
        return 2 * (dims["w"] + dims["h"])
    raise ValueError(f"unknown shape {shape!r}")
