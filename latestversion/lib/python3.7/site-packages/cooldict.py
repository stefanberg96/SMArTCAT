from __future__ import print_function
import collections
import itertools

import ana

import logging
l = logging.getLogger("cooldict")
l.addHandler(logging.NullHandler())

class FinalizedError(Exception):
    pass

class BranchingDictError(Exception):
    pass

default_max_depth = 200
default_min_depth = 100

# for speed, cause the ABC instancecheck is slow
#pylint:disable=unidiomatic-typecheck

############################
### The dicts themselves ###
############################

class CoolDict(ana.Storable, collections.MutableMapping):
    '''
    The base dict class for CoolDict.
    '''

    def _ancestry_line(self):
        '''
        Returns the ancestry of this dict, back to the first dict that we don't
        recognize or that has more than one backer.
        '''
        b = self._get_backers()

        while len(b) == 1:
            yield b[0]
            if not hasattr(b[0], '_get_backers'):
                break
            b = b[0]._get_backers()

    def _get_storage(self):
        '''
        Returns the backend store dict that the cooldict uses.
        '''
        raise NotImplementedError("%s._get_storage" % self.__class__.__name__)

    def _get_backers(self):
        '''
        Returns the backers of the dictionary.
        '''
        raise NotImplementedError("%s._get_backers" % self.__class__.__name__)

    def _get_deleted(self): #pylint:disable=no-self-use
        '''
        Returns the set of deleted items.
        '''
        return set()

class CachedDict(CoolDict):
    ''' Implements a write-through cache around another dict. '''

    def __init__(self, backer):
        self.backer = backer
        self.cache = { }

        self.make_uuid()

    def _get_backers(self):
        return [ self.backer ]

    def _get_storage(self):
        return self.cache

    def default_cacher(self, k):
        v = self.backer[k]
        self.cache[k] = v
        return v

    def __getitem__(self, k):
        try:
            return self.cache[k]
        except KeyError:
            return self.default_cacher(k)

    def __setitem__(self, k, v):
        self.cache[k] = v
        self.backer[k] = v

    def __delitem__(self, k):
        self.cache.pop(k, None)
        self.backer.pop(k, None)

    def __iter__(self):
        return self.backer.__iter__()

    def __len__(self):
        return len(self.backer)

    def _ana_getstate(self):
        return self.backer

    def _ana_setstate(self, state):
        self.backer = state
        self.cache = { }

class BackedDict(CoolDict):
    ''' Implements a mapping that's backed by other mappings. '''

    def __init__(self, *backers, **kwargs):
        self.backers = backers
        self.storage = kwargs.get('storage', { })
        self.deleted = kwargs.get('deleted', set())

        self.make_uuid()

    def _get_backers(self):
        return self.backers

    def _get_deleted(self):
        return self.deleted

    def _get_storage(self):
        return self.storage

    def __getitem__(self, a):
        # make sure we haven't deleted it
        if a in self.deleted:
            raise KeyError(a)

        # return it if we have it in storage
        if a in self.storage:
            return self.storage[a]

        # try the backers
        for p in self.backers:
            try:
                return p[a]
            except KeyError:
                pass

        # panic!
        raise KeyError(a)

    def __delitem__(self, a):
        # make sure we can do it
        if a not in self:
            raise KeyError(a)

        # and do it
        self.storage.pop(a, None)
        self.deleted.add(a)

    def __setitem__(self, k, v):
        self.deleted.discard(k)
        self.storage[k] = v

    def __iter__(self):
        chain = itertools.chain(self.storage, *[ p for p in self.backers ])
        seen = set()
        for k in chain:
            if k not in self.deleted and k not in seen:
                seen.add(k)
                yield k

    def __len__(self):
        return len(list(self.__iter__()))

    def flatten(self):
        l.info("Flattening backers of %s!", self)
        if len(self.backers) > 1:
            l.debug("Slow path")

            s_keys = set(self.storage.keys())
            for b in reversed(self.backers):
                b_keys = set(b.keys())
                for i in b_keys - s_keys:
                    self.storage[i] = b[i]
            self.backers = [ ]
        else:
            a_line = list(self._ancestry_line())
            ancestors = [ (a._get_storage() if hasattr(a, '_get_storage') else a) for a in a_line  ]
            ancestor_keys = [ set(a.keys()) for a in ancestors ]
            remaining = set()
            new_backers = [ ]

            try:
                #print("Checking for ignores")
                ignored_idx = [ getattr(a, 'cooldict_ignore', False) for a in a_line ].index(True)
                #print("... found at",ignored_idx)
                new_backers = [ a_line[ignored_idx] ]
                ancestors = ancestors[:ignored_idx]
                ancestor_keys = ancestor_keys[:ignored_idx]
            except ValueError:
                #print("... not found")
                pass

            #print("ancestors:",ancestors)
            #print("new ancestors:",ancestors)

            for a in reversed(a_line):
                keys = set(a._get_storage().keys()) if hasattr(a, '_get_storage') else set()
                ancestor_keys.append(keys)
                remaining |= keys
                if type(a) is BackedDict:
                    remaining -= a.deleted

            remaining -= set(self.storage.keys())
            remaining -= self.deleted

            for a,keys in zip(ancestors, ancestor_keys):
                toadd = keys & remaining
                if len(toadd) == 0:
                    continue
                l.debug("Adding %d keys from %s", len(toadd), a)
                for k in toadd:
                    self.storage[k] = a[k]
                remaining -= keys

            if len(remaining) != 0:
                raise Exception("%d items remaining after flatten!" % len(remaining))
            self.backers = new_backers

    def _ana_getstate(self):
        return self.storage, self.deleted, self.backers

    def _ana_setstate(self, state):
        self.storage, self.deleted, self.backers = state

class FinalizableDict(CoolDict):
    ''' Implements a finalizable dict. This is meant to support BranchingDict, and offers no guarantee about the actual immutability of the underlying data. It's quite easy to bypass. You've been warned. '''

    def __init__(self, storage = None):
        self.finalized = False
        self.storage = { } if storage is None else storage

        self.make_uuid()

    def _get_backers(self):
        return [ self.storage ]

    def _get_storage(self):
        return { }

    def __getitem__(self, a):
        return self.storage[a]

    def __delitem__(self, a):
        if self.finalized:
            raise FinalizedError("dict is finalized")
        del self.storage[a]

    def __setitem__(self, k, v):
        if self.finalized:
            raise FinalizedError("dict is finalized")
        self.storage[k] = v

    def __iter__(self):
        return self.storage.__iter__()

    def __len__(self):
        return self.storage.__len__()

    def finalize(self):
        self.finalized = True

    def _ana_getstate(self):
        self.finalize()
        return (self.storage,)

    def _ana_setstate(self, state):
        self.storage = state[0]
        self.finalized = True

class COWDict(CoolDict):
    '''
    This implements a copy-on-write dictionary. A COWDict can be branch()ed and
    the two copies will thereafter share a common backer for reads. Writes will
    result in the backer being copied, and the copy being used instead.
    '''

    def __init__(self, cowdict=None):
        self._cowdict = { } if cowdict is None else cowdict
        self._cowed = False

    def _get_backers(self):
        return [ self._cowdict ]

    def _get_storage(self):
        return self._cowdict

    def _cow(self):
        if self._cowed:
            return
        else:
            self._cowed = True
            self._cowdict = dict(self._cowdict)

    def __delitem__(self, k):
        self._cow()
        return self._cowdict.__delitem__(k)

    def __getitem__(self, k):
        return self._cowdict.__getitem__(k)

    def __setitem__(self, k, v):
        self._cow()
        return self._cowdict.__setitem__(k, v)

    def __iter__(self):
        return iter(self._cowdict)

    def __len__(self):
        return len(self._cowdict)

    def clear(self):
        self._cow()
        return self._cowdict.clear()

    def branch(self):
        self._cowed = False
        return COWDict(cowdict=self._cowdict)

    def common_ancestor(self, o):
        if self._cowdict is o._cowdict:
            return self._cowdict
        else:
            return None

    def changes_since(self, ancestor):
        if ancestor is self._cowdict:
            return set(), set()
        elif ancestor is None:
            return set(self.keys()), set()
        else:
            return set(ancestor.keys()) | set(self.keys()), set()

    ancestry_line = CoolDict._ancestry_line

class SinkholeCOWDict(COWDict):
    '''
    This extends COWDict with a "sinkholing" capability. A single
    value can be set that is returned by __missing__.
    '''

    def __init__(self, sinkholed=False, sinkhole_value=None, *args, **kwargs):
        COWDict.__init__(self, *args, **kwargs)
        self._sinkholed = sinkholed
        self._sinkhole_value = sinkhole_value

    def branch(self):
        self._cowed = False
        return SinkholeCOWDict(sinkholed=self._sinkholed, sinkhole_value=self._sinkhole_value, cowdict=self._cowdict)

    def __getitem__(self, k):
        try:
            return COWDict.__getitem__(self, k)
        except KeyError:
            if self._sinkholed:
                return self._sinkhole_value
            else:
                raise

    def sinkhole(self, v, wipe=True):
        self._cow()
        if wipe:
            self.clear()
        self._sinkholed=True
        self._sinkhole_value = v

class BranchingDict(CoolDict):
    '''
    This implements a branching dictionary. Basically, a BranchingDict can be
    branch()ed and the two copies will thereafter share a common backer, but
    will not write back to that backer. Can probably be reimplemented without
    FinalizableDict.
    '''
    def __init__(self, d = None, max_depth = None, min_depth = None):
        max_depth = default_max_depth if max_depth is None else max_depth
        min_depth = default_min_depth if min_depth is None else min_depth

        d = { } if d is None else d
        if not type(d) is FinalizableDict:
            d = FinalizableDict(d)
        self.cowdict = d

        ancestors = list(self.ancestry_line())
        if len(ancestors) > max_depth:
            l.debug("BranchingDict got too deep (%d)", len(ancestors))
            new_dictriarch = None
            for k in ancestors[min_depth:]:
                if type(k) is BackedDict:
                    new_dictriarch = k
                    break
            if new_dictriarch is not None:
                l.debug("Found ancestor %s", new_dictriarch)
                new_dictriarch.flatten()

        self.max_depth = max_depth
        self.min_depth = min_depth

    def _get_storage(self):
        return { }

    def _get_backers(self):
        return [ self.cowdict ]

    ancestry_line = CoolDict._ancestry_line

    # Returns the common ancestor between self and other.
    def common_ancestor(self, other):
        our_line = set([ id(a) for a in self.ancestry_line() ])
        for d in other.ancestry_line():
            if id(d) in our_line:
                return d
        return None

    # Returns the entries created and the entries deleted since the specified ancestor.
    def changes_since(self, ancestor):
        created = set()
        deleted = set()

        for a in self.ancestry_line():
            if a is ancestor:
                break
            elif type(a) is FinalizableDict:
                continue
            elif type(a) is BackedDict:
                created.update(set(a.storage.keys()) - deleted)
                deleted.update(a.deleted - created)
            elif isinstance(a, dict):
                created.update(a.keys())

        return created, deleted

    def __getitem__(self, a):
        return self.cowdict[a]

    def __setitem__(self, k, v):
        if self.cowdict.finalized:
            l.debug("Got a finalized dict. Making a child.")
            self.cowdict = FinalizableDict(BackedDict(self.cowdict.storage))
        self.cowdict[k] = v

    def __delitem__(self, k):
        if self.cowdict.finalized:
            l.debug("Got a finalized dict. Making a child.")
            self.cowdict = FinalizableDict(BackedDict(self.cowdict.storage))
        del self.cowdict[k]

    def __iter__(self):
        return self.cowdict.__iter__()

    def __len__(self):
        return self.cowdict.__len__()

    def branch(self):
        self.cowdict.finalize()
        return BranchingDict(self.cowdict, max_depth=self.max_depth, min_depth=self.min_depth)

def test():
    import pickle

    try:
        import standard_logging # pylint: disable=W0612,
    except ImportError:
        pass

    l.setLevel(logging.DEBUG)

    l.info("Testing basic BackedDict functionality.")
    a = "aa"
    b = "bb"
    c = "cc"
    d = "dd"
    one = 11
    two = 12
    three = 13

    b1 = BackedDict()
    b2 = BackedDict()

    b1[a] = 'a'
    b1[one] = 1
    b2[b] = 'b'

    assert len(b1) == 2
    assert len(b2) == 1
    assert b1[a] == 'a'
    assert b1[one] == 1
    assert b2[b] == 'b'

    b3 = BackedDict(b1, b2)
    b3[c] = c
    assert len(b3) == 4
    assert b3[a] == 'a'
    assert b3[one] == 1
    assert b3[b] == 'b'
    assert b3[c] == c
    assert len(b1) == 2
    assert len(b2) == 1
    assert b1[a] == 'a'
    assert b1[one] == 1
    assert b2[b] == 'b'

    del b3[a]
    assert len(b3) == 3

    l.info("Testing COWDict functionality.")
    d1 = COWDict(b3)
    d2 = d1.branch()
    d3 = d2.branch()

    d1[d] = d
    assert len(b3) == 3
    assert len(d1) == 4
    assert len(d2) == 3
    assert len(d3) == 3
    assert d1[d] == d
    assert d1[b] == 'b'
    assert d1[one] == 1

    d3[b] = "omg"
    assert d3[b] == "omg"
    assert d2[b] == 'b'

    d4 = d3.branch()
    del d4[b]
    del d4[c]

    d5 = d4.branch()
    d5['hmm'] = 5
    d6 = d5.branch()

    da = COWDict()
    da[1] = 'one'
    db = da.branch()
    db.clear()
    assert len(db.items()) == 0
    assert len(da.items()) == 1

    l.info("Testing COWDict ancestry and flattening.")
    assert len(list(d5.ancestry_line())) == 1
    dnew = d5.branch()
    dnew['ohsnap'] = 1
    for _ in range(50):
        dnew = dnew.branch()
        dnew['ohsnap'] += 1
    assert len(list(dnew.ancestry_line())) == 1

    for _ in range(2000):
        #print("Branching dict number", _)
        dnew = dnew.branch()
        dnew['ohsnap'] += 1
    assert len(list(dnew.ancestry_line())) == 1

    common = d4.common_ancestor(d2)
    changed, deleted = d4.changes_since(common)
    assert len(changed) == len(d4)
    assert len(deleted) == 0

    changed, deleted = d6.changes_since(common)
    assert len(changed) == len(d6)
    assert len(deleted) == 0

    d7 = d6.branch()
    common = d7.common_ancestor(d7)
    changed, deleted = d6.changes_since(common)
    assert len(changed) == 0
    assert len(deleted) == 0

    l.info("Testing SinkholeCOWDict")
    da = SinkholeCOWDict()
    try:
        print(da[10])
        assert False
    except KeyError:
        pass

    da.sinkhole(10)
    assert da[10] == 10
    assert da[11] == 10
    assert da['asdf'] == 10
    db = da.branch()
    assert da['asdf'] == 10
    assert db['fdsa'] == 10
    db.sinkhole(20)
    assert da['asdf'] == 10
    assert db['fdsa'] == 20

    l.info("Testing BranchingDict functionality.")
    d1 = BranchingDict(b3)
    d2 = d1.branch()
    d3 = d2.branch()

    d1[d] = d
    assert len(b3) == 3
    assert len(d1) == 4
    assert len(d2) == 3
    assert len(d3) == 3
    assert d1[d] == d
    assert d1[b] == 'b'
    assert d1[one] == 1

    b3.flatten()
    assert len(b3.backers) == 0
    assert len(b3) == 3

    d3[b] = "omg"
    assert d3[b] == "omg"
    assert d2[b] == 'b'

    d4 = d3.branch()
    del d4[b]
    del d4[c]

    d5 = d4.branch()
    d5['hmm'] = 5
    d6 = d5.branch()

    l.info("Testing BranchingDict ancestry and flattening.")
    assert len(list(d5.ancestry_line())) == 5
    dnew = d5.branch()
    dnew['ohsnap'] = 1
    for _ in range(50):
        dnew = dnew.branch()
        dnew['ohsnap'] += 1
    assert len(list(dnew.ancestry_line())) == 56

    for _ in range(2000):
        #print("Branching dict number", _)
        dnew = dnew.branch()
        dnew['ohsnap'] += 1
    assert len(list(dnew.ancestry_line())) == 156

    common = d4.common_ancestor(d2)
    changed, deleted = d4.changes_since(common)
    assert len(changed) == 0
    assert len(deleted) == 2

    changed, deleted = d6.changes_since(common)
    assert len(changed) == 1
    assert len(deleted) == 2

    l.info("Testing CachedDict.")
    b0 = { }
    b4 = BackedDict(storage=b0)
    b4[one] = 'one'
    assert len(b0) == 1
    assert b0[one] == 'one'
    assert len(b4) == 1
    assert b4[one] == 'one'

    b5 = CachedDict(BackedDict(b4))
    assert len(b5) == 1
    assert len(b5.cache) == 0
    assert b5[one] == 'one'
    assert len(b5.cache) == 1
    assert len(b5) == 1
    assert len(b4) == 1
    b5[two] = 2
    assert len(b5) == 2

    b6 = BackedDict({three: 3})
    b6[three] = 3
    assert len(b6) == 1

    l.info("Testing pickling.")
    pb1 = BackedDict({1: '1', 2: '2', 3: '3'})
    pb1_id = pb1.ana_store()

    del pb1
    pb1 = BackedDict.ana_load(pb1_id)
    assert pb1.ana_uuid == pb1_id
    assert len(pb1) == 3
    assert len(pb1.storage) == 0
    assert pb1[2] == '2'

    pb1a = BackedDict.ana_load(pb1_id)
    assert pb1 is pb1a
    del pb1a

    pb2 = BackedDict(pb1, {'a': 1, 'b': 2})
    pb2s = pickle.dumps(pb2, -1)
    del pb2
    pb2 = pickle.loads(pb2s)
    assert pb1 is pb2.backers[0]

    bb1 = BranchingDict(pb2)
    bb2 = bb1.branch()
    bb1[4] = '4'

    assert bb1.common_ancestor(bb2) == pb2
    bb1s = pickle.dumps(bb1, -1)
    del bb1
    bb1 = pickle.loads(bb1s)

    assert bb1.common_ancestor(bb2) == pb2

if __name__ == "__main__":
    test()
