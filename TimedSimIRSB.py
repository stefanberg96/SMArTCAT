#!/usr/bin/env python
"""This module handles constraint generation for IRSBs."""

# because pylint can't load pyvex
# pylint: disable=F0401

import logging
l = logging.getLogger("simuvex.vex.irsb")
#l.setLevel(logging.DEBUG)

import pyvex
from simuvex.s_run import SimRun
import simuvex.vex.irsb

import timeStmt
import timeExecution


class IMark(object):
    """
    An IMark is an IR statement that indicates the address and length of the original instruction.
    """
    def __init__(self, i):
        self.addr = i.addr
        self.len = i.len

#pylint:disable=unidiomatic-typecheck


class TimedSimIRSB(simuvex.vex.SimIRSB):
    """
    Symbolically parse a basic block.

    :ivar irsb:             The pyvex IRSB to parse.
    :ivar provided_state:   The symbolic state at the beginning of the block.
    :ivar id:               The ID of the basic block.
    :ivar whitelist:        A whitelist of the statements to execute. (default: all)
    :ivar last_stmt:        The statement to stop execution at.
    """

    def __init__(self, state, irsb, irsb_id=None, whitelist=None, last_stmt=None, force_bbl_addr=None, **kwargs):
        simuvex.vex.SimIRSB.__init__(self, state, irsb, irsb_id=None, whitelist=None, last_stmt=None, force_bbl_addr=None, **kwargs)


    # This function receives an initial state and imark and processes a list of pyvex.IRStmts
    # It returns a final state, last imark, and a list of SimIRStmts
    def _handle_statements(self):
        # Translate all statements until something errors out
        stmts = self.irsb.statements

        skip_stmts = 0
        if o.SUPER_FASTPATH in self.state.options:
            # Only execute the last but two instructions
            imark_counter = 0
            for i in xrange(len(stmts) - 1, -1, -1):
                if type(stmts[i]) is pyvex.IRStmt.IMark:
                    imark_counter += 1
                if imark_counter >= 2:
                    skip_stmts = i
                    break

        for stmt_idx, stmt in enumerate(stmts):
            if self.last_stmt is not None and stmt_idx > self.last_stmt:
                l.debug("%s stopping analysis at statement %d.", self, self.last_stmt)
                break

            if stmt_idx < skip_stmts:
                continue

            #l.debug("%s processing statement %s of max %s", self, stmt_idx, self.last_stmt)
            self.state.scratch.stmt_idx = stmt_idx
    
            # we'll pass in the imark to the statements
            if type(stmt) == pyvex.IRStmt.IMark:
                self.last_imark = IMark(stmt)
                self.state.scratch.ins_addr = stmt.addr + stmt.delta

                for subaddr in xrange(stmt.addr, stmt.addr + stmt.len):
                    if subaddr in self.state.scratch.dirty_addrs:
                        raise SimReliftException(self.state)
                self.state._inspect('instruction', BP_AFTER)

                l.debug("IMark: %#x", stmt.addr)
                self.state.scratch.num_insns += 1
                if o.INSTRUCTION_SCOPE_CONSTRAINTS in self.state.options:
                    if 'solver_engine' in self.state.plugins:
                        self.state.release_plugin('solver_engine')

                self.state._inspect('instruction', BP_BEFORE, instruction=self.last_imark.addr)

            if self.whitelist is not None and stmt_idx not in self.whitelist:
                l.debug("... whitelist says skip it!")
                continue
            elif self.whitelist is not None:
                l.debug("... whitelist says analyze it!")

            # process it!
            self.state._inspect('statement', BP_BEFORE, statement=stmt_idx)
            
            #added code to bypass the checks for "supported" vex statements
            if type(stmt) == timeStmt.Time:
                s_stmt = timeExecution.SimIRStmt_Time(self.irsb, stmt_idx, self.last_imark, self.state)
                s_stmt.process()
            else:
                s_stmt = translate_stmt(self.irsb, stmt_idx, self.last_imark, self.state)
            if s_stmt is not None:
                self.state.log.extend_actions(s_stmt.actions)
            self.statements.append(s_stmt)
            self.state._inspect('statement', BP_AFTER)

            # for the exits, put *not* taking the exit on the list of constraints so
            # that we can continue on. Otherwise, add the constraints
            if type(stmt) == pyvex.IRStmt.Exit:
                l.debug("%s adding conditional exit", self)

                e = self.add_successor(self.state.copy(), s_stmt.target, s_stmt.guard, s_stmt.jumpkind, stmt_idx)
                self.conditional_exits.append(e)
                self.state.add_constraints(self.state.se.Not(s_stmt.guard))
                self.default_exit_guard = self.state.se.And(self.default_exit_guard, self.state.se.Not(s_stmt.guard))

                if o.SINGLE_EXIT in self.state.options and e.satisfiable():
                    l.debug("%s returning after taken exit due to SINGLE_EXIT option.", self)
                    return

        if self.last_stmt is None:
            self.has_default_exit = True
            
from simuvex.vex.statements import translate_stmt
from simuvex.vex.expressions import translate_expr

from simuvex.vex import size_bits
from simuvex import s_options as o
from simuvex.plugins.inspect import BP_AFTER, BP_BEFORE
from simuvex.s_errors import SimError, SimIRSBError, SimSolverError, SimMemoryAddressError, SimReliftException
from simuvex.s_action import SimActionExit, SimActionObject