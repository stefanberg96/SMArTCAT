import angr
import timing
import timedFactory
import metaplugin
import claripy
import pathTimeComparison
import analysisUtils
a2i = analysisUtils.a2i
    

b = angr.Project("reverseme")
#pswp = claripy.BVS("password", 32)
startState = b.factory.call_state(0x000089B4, 0xbbbb0000)
#startState = b.factory
startstate.se.add(pswp == 0xbbbb0000)
tpg = b.factory.path_group()

#tpg.explore(find=0x00008D80)

for d in tpg.deadended:
    if(d.state.se.satisfiable):
        d.state.se.any_n_str(d.state.memory.load(0xbbbb0000, 8),10)


#runs an analysis, outputs some timing information

print "running simple analysis on ./a.out"

import angr
import timing
import timedFactory
import metaplugin
import claripy
import pathTimeComparison
import analysisUtils as u

public = claripy.BVS("publicArgument", 32)
secret = claripy.BVS("secretArgument", 32)
f
    startState = b.factory.call_state(u.functionAddress("pinToByte",b.filename), public, secret)
    startState.meta.factory = tf
    tpg = tf.path_group(startState)
    tpg.explore()