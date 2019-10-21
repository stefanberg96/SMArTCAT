import logging
l = logging.getLogger('ana.d')

def D(uuid, child_cls, state):
    l.debug("Deserializing Storable with uuid %s", uuid)

    if uuid is None and state is None:
        raise ANAError("A blank UUID and a blank state were passed into the deserialization routine. This is most likely caused by a failure to return anything from object._ana_getstate().")

    if uuid is not None:
        self = get_dl().uuid_cache.get(uuid, None)
        if self is not None:
            l.debug("... returning cached")
            return self

    self = super(Storable, child_cls).__new__(child_cls) #pylint:disable=bad-super-call
    dl = get_dl()
    if uuid is not None:
        dl.uuid_cache[uuid] = self

    if uuid is not None and state is None:
        l.debug("... loading state")
        state = get_dl().load_state(uuid)

    if uuid is not None:
        self._stored = dl.uuid
        l.debug("... returning newly cached")
    else:
        self._stored = None
        l.debug("... returning non-UUID storable")

    self._ana_setstate(state)
    self._ana_uuid = uuid

    if not hasattr(self, '_ana_uuid'):
        raise ANAError("Storable somehow got through without an _ana_uuid attr")
    return self

D.__safe_for_unpickling__ = True

from .storable import Storable
from .errors import ANAError
from . import get_dl
