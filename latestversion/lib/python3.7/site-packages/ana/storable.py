from future.utils import iteritems
from past.builtins import long, unicode
import uuid as uuid_module

import logging
l = logging.getLogger('ana.storable')

def _all_slots(cls):
    return sum((o.__slots__ for o in cls.mro() if hasattr(o, '__slots__') and not o is Storable),[])

class Storable(object):
    __slots__ = [ '_ana_uuid', '_stored', '__weakref__' ]

    def make_uuid(self, uuid=None):
        '''
        If the storable has no UUID, this function creates one. The UUID is then
        returned.
        '''
        u = getattr(self, '_ana_uuid', None)
        if u is None:
            u = str(uuid_module.uuid4()) if uuid is None else uuid
            l.debug("Caching UUID %s", u)
            get_dl().uuid_cache[u] = self
            setattr(self, '_ana_uuid', u)
        return u

    @property
    def ana_uuid(self):
        return self.make_uuid()

    def ana_store(self):
        '''
        Assigns a UUID to the storable and stores the actual data.
        '''
        u = self.make_uuid()
        dl = get_dl()
        if not getattr(self, '_stored', None) == dl.uuid:
            state = self._ana_getstate()
            setattr(self, '_stored', dl.uuid)
            dl.store_state(u, state)
        return u

    @classmethod
    def ana_load(cls, uuid):
        return D(uuid, cls, get_dl().load_state(uuid))

    @staticmethod
    def _any_to_literal(o, known_set, objects):
        if o is None:
            return None
        elif type(o) in (long, int, str, unicode, float, bool):
            return o
        elif isinstance(o, dict):
            return {
                Storable._any_to_literal(k, known_set, objects):Storable._any_to_literal(v, known_set, objects) for k,v in iteritems(o)
            }
        elif isinstance(o, list) or isinstance(o, tuple) or isinstance(o, set):
            return [ Storable._any_to_literal(e, known_set, objects) for e in o ]
        elif isinstance(o, Storable):
            return o._self_to_literal(known_set, objects)
        else:
            if hasattr(o, '__getstate__'):
                state = o.__getstate__()
            elif hasattr(o, '__dict__'):
                state = o.__dict__
            else:
                state = { k: getattr(o, k) for k in _all_slots(o.__class__)  }

            return {
                'class': o.__class__.__name__,
                'object': Storable._any_to_literal(state, known_set, objects)
            }

    def _self_to_literal(self, known_set, objects):
        uuid = self.make_uuid()

        if uuid not in known_set:
            known_set.add(uuid)
            o = self._ana_getliteral()
            objects[uuid] = {
                #'module': getattr(self, '__module__', '__unknown__'),
                'class': self.__class__.__name__,
                'object': self._any_to_literal(o, known_set, objects)
            }

        return { 'ana_uuid': uuid }

    def to_literal(self, known_set=None, objects=None):
        if known_set is None:
            known_set = set()

        objects = { } if objects is None else objects
        return { 'objects': objects, 'value': self._self_to_literal(known_set, objects) }

    #
    # ANA API
    #

    @classmethod
    def _all_slots(cls):
        #pylint:disable=no-member
        return _all_slots(cls)

    def _ana_getstate(self):
        if hasattr(self, '__dict__'):
            return self.__dict__
        else:
            return { k: getattr(self, k) for k in self._all_slots() if hasattr(self, k) }

    def _ana_setstate(self, s):
        for k,v in iteritems(s):
            setattr(self, k, v)

    def _ana_getliteral(self):
        return self._ana_getstate()

    #
    # Pickle API
    #

    def __reduce__(self):
        u = getattr(self, '_ana_uuid', None)
        if u is None:
            return (D, (None, self.__class__, self._ana_getstate()))
        elif get_dl()._store_type == 'simple':
            return (D, (u, self.__class__, self._ana_getstate()))
        else:
            self.ana_store()
            return (D, (u, self.__class__, None))


from . import get_dl
from .d import D
