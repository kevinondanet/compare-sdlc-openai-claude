import unittest

from shapes import area, perimeter


class ShapesTest(unittest.TestCase):
    def test_rectangle(self) -> None:
        self.assertEqual(area("rectangle", w=2.0, h=3.0), 6.0)
        self.assertEqual(perimeter("rectangle", w=2.0, h=3.0), 10.0)

    def test_unknown(self) -> None:
        with self.assertRaises(ValueError):
            area("hexagon", r=1.0)
