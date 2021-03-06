# coding=utf-8
#
# This file is part of Hypothesis (https://github.com/DRMacIver/hypothesis)
#
# Most of this work is copyright (C) 2013-2015 David R. MacIver
# (david@drmaciver.com), but it contains contributions by others. See
# https://github.com/DRMacIver/hypothesis/blob/master/CONTRIBUTING.rst for a
# full list of people who may hold copyright, and consult the git log if you
# need to determine who owns an individual contribution.
#
# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at http://mozilla.org/MPL/2.0/.
#
# END HEADER

from __future__ import division, print_function, absolute_import

import hypothesis.internal.conjecture.utils as d
from hypothesis.types import RandomWithSeed
from hypothesis.searchstrategy.strategies import SearchStrategy, \
    MappedSearchStrategy


class BoolStrategy(SearchStrategy):

    """A strategy that produces Booleans with a Bernoulli conditional
    distribution."""

    def __repr__(self):
        return u'BoolStrategy()'

    def do_draw(self, data):
        return d.boolean(data)


class JustStrategy(SearchStrategy):

    """
    A strategy which simply returns a single fixed value with probability 1.
    """

    def __init__(self, value):
        SearchStrategy.__init__(self)
        self.value = value

    def __repr__(self):
        return 'JustStrategy(value=%r)' % (self.value,)

    def do_draw(self, data):
        return self.value


class RandomStrategy(MappedSearchStrategy):

    """A strategy which produces Random objects.

    The conditional distribution is simply a RandomWithSeed seeded with
    a 128 bits of data chosen uniformly at random.

    """

    def pack(self, i):
        return RandomWithSeed(i)


class SampledFromStrategy(SearchStrategy):

    """A strategy which samples from a set of elements. This is essentially
    equivalent to using a OneOfStrategy over Just strategies but may be more
    efficient and convenient.

    The conditional distribution chooses uniformly at random from some
    non-empty subset of the elements.

    """

    def __init__(self, elements):
        SearchStrategy.__init__(self)
        self.elements = tuple(elements)
        assert self.elements

    def do_draw(self, data):
        return d.choice(data, self.elements)
