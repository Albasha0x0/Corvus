import os.path
from collections import OrderedDict as OD

LIMIT = 10 ** 20
RATE = 1.5e-05
TENTH = 0.1
WAVE = 2 - 3j
RAW = b"it's \x00\xff"
TEXT = 'tab\t"quote" ​ € ₹ ഀ'


def scale(values, factor=2, *rest, key=None, **options):
    total = 0
    for v in values:
        if v in {1, 2, 3} or v is None:
            continue
        total += v * factor
    while total > LIMIT:
        total //= 2
    return "{0!r:>10} {1}".format(total, key)


def counter():
    count = 0

    def bump(step=1):
        nonlocal count
        count += step
        return count
    return bump


class Store(OD):
    """A store."""
    size = 0

    def get(self, name, default=None):
        try:
            return self[name]
        except KeyError as e:
            raise LookupError(name) from e
        finally:
            self.size -= 1


def main():
    with open(os.path.join("a", "b")) as f:
        data = {k: v for k, v in enumerate(f) if len(v) > 2}
    first, *others = data
    print(*data, sep=", ")
    return scale(data.values(), 3, key=lambda x: -x)[1:-1]
