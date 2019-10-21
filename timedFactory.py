from simuvex import SimIRSB, SimProcedures, SimUnicorn, SimState, BP_BEFORE, BP_AFTER, SimUnicornError
from simuvex import s_options as o, s_cc
from simuvex.s_errors import SimSegfaultError, SimReliftException
from angr.surveyors.caller import Callable

import angr.factory

import TimedSimIRSB
import TimeLifter
import timingModel

import logging
l = logging.getLogger('angr.factory')

class TimedAngrObjectFactory(angr.factory.AngrObjectFactory):
    def __init__(self, project, translation_cache=False):
        #angr.factory.AngrObjectFactory.__init__(self, project, translation_cache)
        self._project = project
        self._lifter = TimeLifter.TimeLifter(project, cache=translation_cache)
        self.block = self._lifter.lift
        self.fresh_block = self._lifter.fresh_block
        self._default_cc = s_cc.DefaultCC[project.arch.name]

        
    def sim_block(self, state, stmt_whitelist=None, last_stmt=None,
                  addr=None, opt_level=None, **block_opts):
        """
        Returns a SimIRSB object with execution based on state.

        :param state:           The state to tick forward with this block.

        The following parameters are optional:

        :param stmt_whitelist:  A list of stmt indexes to which to confine execution.
        :param last_stmt:       A statement index at which to stop execution.
        :param addr:            The address at which to start the block.
        :param thumb:           Whether the block should be lifted in ARM's THUMB mode.
        :param backup_state:    A state to read bytes from instead of using project memory.
        :param opt_level:       The VEX optimization level to use.
        :param insn_bytes:      A string of bytes to use for the block instead of the project.
        :param max_size:        The maximum size of the block, in bytes.
        :param num_inst:        The maximum number of instructions.
        :param traceflags:      traceflags to be passed to VEX. Default: 0
        """

        if 'thumb' in block_opts:
            raise AngrValueError('You are not allowed to pass in a thumb=x property to sim_block')

        if addr is None:
            addr = state.se.any_int(state.regs.ip)

        if o.STRICT_PAGE_ACCESS in state.options:
            try:
                perms = state.memory.permissions(addr)
            except KeyError:
                raise SimSegfaultError(addr, 'exec-miss')
            else:
                if not perms.symbolic:
                    perms = perms.args[0]
                    if not perms & 4:
                        raise SimSegfaultError(addr, 'non-executable')

        thumb = False
        if addr % state.arch.instruction_alignment != 0:
            if state.thumb:
                thumb = True
            else:
                raise AngrExitError("Address %#x does not align to alignment %d "
                                    "for architecture %s." % (addr,
                                    state.arch.instruction_alignment,
                                    state.arch.name))

        if opt_level is None:
            opt_level = 1 if o.OPTIMIZE_IR in state.options else 0

        force_bbl_addr = block_opts.pop('force_bbl_addr', None)

        while True:
            bb = self.block(addr,
                            arch=state.arch,
                            opt_level=opt_level,
                            thumb=thumb,
                            backup_state=state,
                            **block_opts)

            try:
                return TimedSimIRSB.TimedSimIRSB(state,
                               bb.vex,
                               addr=addr,
                               whitelist=stmt_whitelist,
                               last_stmt=last_stmt,
                               force_bbl_addr=force_bbl_addr)
            except SimReliftException as e:
                state = e.state
                force_bbl_addr = state.scratch.bbl_addr
                if 'insn_bytes' in block_opts:
                    raise AngrValueError("You cannot pass self-modifying code as insn_bytes!!!")
                new_ip = state.scratch.ins_addr
                if 'max_size' in block_opts:
                    block_opts['max_size'] -= new_ip - addr
                if 'num_inst' in block_opts:
                    block_opts['num_inst'] -= state.scratch.num_insns
                addr = new_ip

from angr.errors import AngrExitError, AngrError, AngrValueError, AngrUnsupportedSyscallError
from angr.path import Path
from angr.path_group import PathGroup
from angr.knowledge import HookNode