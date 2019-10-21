#!/usr/bin/env python
#plugin to keep track of state execution time
#TODO: add counters for branch prediction and caching violations

import logging
l = logging.getLogger("simuvex.plugins.time")

import claripy

from simuvex.plugins.plugin import SimStatePlugin

class SimStateTime(SimStatePlugin):
    def __init__(self, time=None):
        SimStatePlugin.__init__(self)

        # info on the current run
        self.totalExecutionTime = claripy.BVV(0x000000, 32)

        if time is not None:
            self.totalExecutionTime = time.totalExecutionTime

    def countTime(self, deltaTime):
        self.totalExecutionTime += deltaTime
        return True

    def copy(self):
        return SimStateTime(time=self)

    def merge(self, others, merge_conditions, common_ancestor=None):
		#TODO
        return False

    def widen(self, others):
        return False

    def clear(self):
        s = self.state
        self.__init__()
        self.state = s

SimStateTime.register_default('time', SimStateTime)