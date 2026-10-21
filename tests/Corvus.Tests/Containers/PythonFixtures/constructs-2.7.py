import os.path
from collections import OrderedDict as OD

LIMIT = 10 ** 20
BIG = 18446744073709551616L
RATE = 1.5e-05
WAVE = 2 - 3j
RAW = "it's \x00\xff"
TEXT = u'tab\t"quote" ​'


def scale(values, factor=2, *rest, **options):
    total = 0
    for v in values:
        if v in (1, 2, 3) or v is None:
            continue
        total += v * factor
    while total > LIMIT:
        total //= 2
    print >> options.get("out"), "%r" % total
    return total


def counter():
    count = [0]

    def bump(step=1):
        count[0] += step
        return count[0]
    return bump


class Store(OD):
    """A store."""

    def get(self, name, default=None):
        try:
            try:
                return self[name]
            except KeyError, e:
                raise LookupError(name)
        finally:
            self.size -= 1


def main():
    with open(os.path.join("a", "b")) as f:
        data = dict((k, v) for k, v in enumerate(f) if len(v) > 2)
    exec "x = 1" in data
    return scale(data.values(), 3)[1:-1]
