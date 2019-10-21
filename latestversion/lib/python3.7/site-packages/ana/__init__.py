#pylint:disable=wildcard-import

import logging
logging.getLogger("ana").addHandler(logging.NullHandler())

from .datalayer import *

dl = SimpleDataLayer()
def get_dl():
    return dl
def set_dl(new_dl):
    global dl
    dl = new_dl

class M(object):
    '''This is a marker that's used internally by ANA.'''
    __slots__ = [ ]

from .storable import *
