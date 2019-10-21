import os
import uuid as uuid_module
import weakref

try:
    import cPickle as pickle
except ImportError:
    import pickle

try:
    import pymongo
    import bson
except ImportError:
    # mongo dependency is optional
    pymongo = None

import logging
l = logging.getLogger("ana.datalayer")

class DataLayer(object):
    '''
    The DataLayer handles storing and retrieving UUID-identified objects
    to/from a central store.
    '''

    def __init__(self):
        self.uuid_cache = weakref.WeakValueDictionary()
        self._store_type = None
        self.uuid = uuid_module.uuid4()

    def store_state(self, uuid, s):
        raise NotImplementedError()

    def load_state(self, uuid):
        raise NotImplementedError()

class SimpleDataLayer(DataLayer):
    def __init__(self):
        DataLayer.__init__(self)
        self._store_type = 'simple'

    def store_state(self, uuid, s):
        return

    def load_state(self, uuid):
        raise ANAError("SimpleDataLayer does not support state loading.")

class DirDataLayer(DataLayer):
    def __init__(self, pickle_dir):
        DataLayer.__init__(self)
        self._store_type = 'pickle'
        self._dir = pickle_dir

        if not os.path.exists(self._dir):
            l.warning("Directory '%s' doesn't exit. Creating.", self._dir)
            os.makedirs(self._dir)

    def store_state(self, uuid, s):
        with open(os.path.join(self._dir, str(uuid)+'.p'), 'wb') as f:
            pickle.dump(s, f, protocol=pickle.HIGHEST_PROTOCOL)

    def load_state(self, uuid):
        with open(os.path.join(self._dir, str(uuid)+'.p'), 'rb') as f:
            return pickle.load(f)

class MongoDataLayer(DataLayer):
    def __init__(self, mongo_args, mongo_db='ana', mongo_collection='storage'):
        DataLayer.__init__(self)
        if pymongo is None:
            raise ImportError("pymongo necessary for ANA mongo backend")

        l.debug("Pickling into mongo.")

        self._store_type = 'mongo'
        self._mongo = pymongo.MongoClient(*mongo_args)[mongo_db][mongo_collection]

    def store_state(self, uuid, s):
        # TODO: investigate whether check/insert is faster than
        # upsert (because of latency) and also deal with the race
        # condition here
        if self._mongo.find({'_id': uuid}).limit(1).count(with_limit_and_skip=True) == 0:
            p = pickle.dumps(s, protocol=pickle.HIGHEST_PROTOCOL)
            self._mongo.insert_one({'_id': uuid, 'pickled': bson.binary.Binary(p)})

    def load_state(self, uuid):
        p = self._mongo.find_one({'_id': uuid})['pickled']
        return pickle.loads(p)

class DictDataLayer(DataLayer):
    def __init__(self, the_dict=None):
        DataLayer.__init__(self)
        self._store_type = 'dict'
        self._state_store = { } if the_dict is None else the_dict

    def store_state(self, uuid, s):
        p = pickle.dumps(s, protocol=pickle.HIGHEST_PROTOCOL)
        self._state_store[uuid] = p

    def load_state(self, uuid):
        p = self._state_store[uuid]
        return pickle.loads(p)

from .errors import ANAError
