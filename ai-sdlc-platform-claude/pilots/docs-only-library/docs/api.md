# shapes — API reference

The `shapes` package exposes two pure functions. Every example below is executed by
`python3 -m doctest docs/api.md` (the change's verification command).

## shapes.area

`area(shape, **dims) -> float` — area of a `"circle"` (`r`) or `"rectangle"` (`w`, `h`).

```
>>> from shapes import area
>>> area("rectangle", w=2.0, h=3.0)
6.0

```

Raises `ValueError` for an unknown shape name.

## shapes.perimeter

`perimeter(shape, **dims) -> float` — perimeter with the same keyword arguments.

```
>>> from shapes import perimeter
>>> perimeter("rectangle", w=2.0, h=3.0)
10.0

```
