import unittest


def increment(x):
    return x + 1


class ShallPassTest(unittest.TestCase):
    def test(self):
        self.assertEqual(increment(3), 4)
