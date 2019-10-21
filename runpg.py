from __future__ import print_function
import angr
import timing
import timedFactory
import metaplugin
import claripy
import pathTimeComparison
#ta = pathTimeComparison.TimeAnalysis()
import analysisUtils
a2i = analysisUtils.a2i
    

b = angr.Project("/media/sf_share/a.out")
#b = angr.Project("/home/roeland/Documents/programs/fauxware/fauxware")
tf = timedFactory.TimedAngrObjectFactory(b)
b.factory = tf
startState = b.factory.blank_state(addr=0x400646)
#startState = b.factory.entry_state()
startState.meta.factory = tf
#0x7fffffffffeff58
tpg = tf.path_group(startState)
tpg.explore()

print("%d paths deadended" % len(tpg.deadended))
for i,d in enumerate(tpg.deadended):
    print("==================================================================================")
    print("analyzing deadended path %d" % i)
    s = d.state
    timingsForThisPath = s.se.eval(s.time.totalExecutionTime,10)
    print("timings:")
    print(timingsForThisPath)
    print("----------------------------------------------------------------------------------")
    if len(timingsForThisPath) > 1:
        print("pre time lock-in:")   
    else:
        print("time automaticlaly locked in because single possible timing for this path: %d" % timingsForThisPath[0])
    analysisUtils.printEvalAllVariables(s.se, 10)
    # compute the secret from the sdtin chars
    sec = analysisUtils.stringToVar('reg_40_2_64',s.se.constraints)
    #sec = a2i([analysisUtils.stringToVar('file_/dev/stdin_48_0_9_8',s.se.constraints), analysisUtils.stringToVar('file_/dev/stdin_48_1_6_8',s.se.constraints), analysisUtils.stringToVar('file_/dev/stdin_48_2_8_8',s.se.constraints)])
    print("secret:")
    secresolution = s.se.eval(sec, 10)
    print("# resolved options = %d" % len(secresolution))
    print(secresolution)
    if (len(timingsForThisPath) > 1):
        for time in timingsForThisPath:
            ss = s.copy()
            t = claripy.BVS('t',32)
            ss.se.add(t == time)
            ss.se.add(t == ss.time.totalExecutionTime)
            print("----------------------------------------------------------------------------------")
            print("post time lock-in for T = %d" % time)
            analysisUtils.printEvalAllVariables(ss.se)
            # compute the secret from the sdtin chars
            sec = analysisUtils.stringToVar('reg_40_2_64',s.se.constraints)
            #sec = a2i([analysisUtils.stringToVar('file_/dev/stdin_48_0_9_8',ss.se.constraints), analysisUtils.stringToVar('file_/dev/stdin_48_1_6_8',ss.se.constraints), analysisUtils.stringToVar('file_/dev/stdin_48_2_8_8',ss.se.constraints)])
            #sec = a2i(analysisUtils.stringToVar('file_/dev/stdin_48_0_9_8' ,ss.se.constraints))*100 + a2i(analysisUtils.stringToVar('file_/dev/stdin_48_1_6_8' ,ss.se.constraints))*10 + a2i(analysisUtils.stringToVar('file_/dev/stdin_48_2_8_8' ,ss.se.constraints))
            print("secret:")
            secresolution = ss.se.eval(sec, 10)
            print("# resolved options = %d" % len(secresolution))
            print(secresolution)

