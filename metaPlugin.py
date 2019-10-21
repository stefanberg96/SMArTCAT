#!/usr/bin/env python
#plugin to keep track of meta data such as the factory

import logging
l = logging.getLogger("simuvex.plugins.meta")

import claripy

from angr.state_plugins.plugin import SimStatePlugin
from angr.sim_state import SimState
class SimStateMeta(SimStatePlugin):
    def __init__(self, meta=None):
        SimStatePlugin.__init__(self)
        
        if meta is not None:
            self.factory = meta.factory
        
    def copy(self, memo):
        return SimStateMeta(meta=self)

    def merge(self, others, merge_conditions, common_ancestor=None):
		#TODO
        return False

    def widen(self, others):
        return False

    def clear(self):
        s = self.state
        self.__init__()
        self.state = s

SimState.register_default('meta', SimStateMeta)
