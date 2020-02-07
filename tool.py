from __future__ import print_function
print("/===========================================================\\")
print("||                                                         ||")
print("||                        SMArTCAT                         ||")
print("||                                                         ||")
print("||           Symbolically Modelled Architecture            ||")
print("||              Timing Channel Analysis Tool               ||")
print("||                                                         ||")
print("||                         /\___/\                         ||")
print("||                        / o   o \                        ||")
print("||                        \  >v<  /                        ||")
print("||                         \_____/                         ||")
print("||                                                         ||")
print("\\===========================================================/")

import init
init.init()

import angr

import claripy
import kcul

import timeAnalysis as t

import sys

import time as TIMER
startTotalTime = TIMER.clock()

import store

import settings

#0: run code
#run some code and merge all constraints

timeSymbol = claripy.BVS("time",32)
#compositions = []
def run():
    """
    We run the symbolic execution, and turn all self-composition constraint sets into one big constraint set expressing all possible self-compositions, and return this in a solver object.
    """
    t.step0()
    startRunTime = TIMER.clock()
    t.step1()

    print("\nSymbolic execution took: %f seconds" % (TIMER.clock() - startRunTime))
    print("\n====================== Post-Analysis ========================\n")
    a = []
    inequalities = set([])
    #global compositions
    for k,d in enumerate(store.tpg.deadended):
        #compositions.append(d.state.se._stored_solver.branch())
        #compositions[k].addInequalityConnector(timeSymbol)
        #compositions[k].add(timeSymbol == d.state.time.totalExecutionTime)
        if d.solver.satisfiable():
            a.append( claripy.And(timeSymbol == d.time.totalExecutionTime, *(d.solver._stored_solver.constraints)) )
    if len(store.tpg.deadended) > 0:
        sol = store.tpg.deadended[0].solver._stored_solver.blank_copy()
    else:
        from selfComposition import SelfComposition
        sol = SelfComposition()
    sol.addInequalityConnector(settings.secret)
    sol.addInequalityConnector(timeSymbol)
    sol.add(claripy.Or(*a))
    sol.simplify()
    return sol

solver = run()

if not settings.PC_ONLY:
    store.solver = solver
    
    print("solutions:")
    
    #1: freeup variables in each constraint to gain as limited relations s E k as possible.
    #let's try and make that code more readable.
    def makeReadables(solver):
        print("computing readable relations on secret...", end='')
        sys.stdout.flush()
        readableSolver = solver.branch()
        readable = kcul.mergeFreeIteratively(readableSolver.constraints[0], settings.secret)
        readable = kcul.mergeReversed(readable, settings.secret)
        readable = kcul.deobfuscateSignComparisons(readable, readableSolver)
        readables = kcul.extractRelations(readable, settings.secret)
        print("\r", end='')
        sys.stdout.flush()
        return readables
    
    readables = []
    #readables = makeReadables(solver)
    
    #for r in readables:
    #    print("readable: %s" % r)
    
    #self composition:
    print("preparing self-composition...", end='')
    sys.stdout.flush()
    sec1 = settings.secret.reversed
    
    #add some auxiliary constraints for our specific scenario:
    #actually this may not be true but lets just assume it for now because its easier that way
    #set1.solver.add(pub1.SGE(-128))
    #set1.solver.add(pub1.SGT(0))
    #set1.solver.add(sec1.SGE(0))
    #set1.solver.add(sec1.SGT(0))
    #set1.solver.add(sec1.SGE(-255))
    #set1.solver.add(pub1.SLE(127))
    #set1.solver.add(sec1.SLE(255))
    
    secret = settings.secret.args[0]
    time = timeSymbol.args[0]
    public = settings.public.args[0]
    
    print("\r                                         \r", end='')
    sys.stdout.flush()
    
    symbols = solver.symbols()
    
    if not (public in symbols and secret in symbols and time in symbols):
        print("program execution constraints do not depend on both public and secret symbols")
    elif not public in symbols:
        print("program execution constraints do not depend on public symbol")
    
    if secret in symbols:
        if not (solver.hasMultipleSolutions(timeSymbol)):
            print("constant timing, no timing channel present")
        else:

            print("performing self-composition analysis...", end='')
            sys.stdout.flush()
            
            satisfiability = solver.satisfiable()
            print("\r                                                   \r", end='')
            sys.stdout.flush()
            if not satisfiability:
                print("self composition is unsatisfiable, no identifiable timing channel")
                #print(solver.constraints)
            else:
                #v 4: compute dynamic range.
                print("\033[93midentified possible timing channel\033[0m")
                
                print("channel analysis INCLUDING channels based on branch prediction and cache attacks:")
                timingsBefore = solver.eval(timeSymbol,100);
                if (len(timingsBefore) >= 100):
                    print("100 or more possible timings.. you may need to consider limiting this somehow")
                else:
                    print("%d possible timings" % len(timingsBefore))
                
                print("max channel dynamic range: (%d, %d)" % solver.dynamicRange(timeSymbol))
                print("max channel dynamic ratio: (%d, %d)" % solver.dynamicRatio(timeSymbol))
                
                import timingModel
                solverLimited = solver.branch()
                if len(timingModel.branchSwitchInstances) > 0:
                    print("channel analysis EXCLUDING channels based on branch prediction attacks:")
                    timingModel.modelBranchMisses(solverLimited,False)
                    if solverLimited.satisfiable():
                        timingsLimited = solverLimited.eval(timeSymbol,100);
                        if (len(timingsLimited) >= 100):
                            print("100 or more possible timings.. you may need to consider limiting this somehow")
                        else:
                            print("%d possible timings:" % len(timingsLimited))
                            print(sorted(timingsLimited))
                            
                        print("max dynamic range: (%d, %d)" % solverLimited.dynamicRange(timeSymbol))
                    else:
                        print("composition is unsatisfiable, these channels don't exist")
                else:
                    print("no branch-predicition-based timing channels present")
                        
                solverLimited = solver.branch()
                if timingModel.cacheSwitch:
                    print("channel analysis EXCLUDING channels based on cache attacks:")
                    
                    timingModel.modelCacheMisses(solverLimited,False)
                    if solverLimited.satisfiable():
                        timingsLimited = solverLimited.eval(timeSymbol,100);
                        if (len(timingsLimited) >= 100):
                            print("100 or more possible timings.. you may need to consider limiting this somehow")
                        else:
                            print("%d possible timings:" % len(timingsLimited))
                            print(sorted(timingsLimited))
                    
                        print("max dynamic range: (%d, %d)" % solverLimited.dynamicRange(timeSymbol))
                    else:
                        print("composition is unsatisfiable, these channels don't exist")
                else:
                    print("no cache-based timing channels present")
                if (max(timingsBefore) >= 100 or max(timingsBefore) != timingsLimited):
                    print("\n------------------------------------------------------------\n")
                    print("continuing analysis on channels INCLUDING channels based on branch prediction and cache attacks.")
                    print("if you want to exclude them, set timingModel.modelCacheMisses(solver, False) / timingModel.modelBranchMisses(solver, False)")
                    #timingModel.modelCacheMisses(solver,True)
                
                # 5: add s R k and s' !R k   ( limit k to max and min s, s'? (not sure if actually needed))
                # 6: see if t already concretized
                #for each s R k in known relations, add above constraints in a branch and see whether t becomes concrete

                #gather all relations s R k
                relations = set()
                for r in readables:
                    relations.add(r.op)

                print("identified relations on secret: %s" % relations)
                
                
                print("skipping relational analysis... to turn on, change the code after this print statement ;)")
                relations = [];
                
                
                #check whether timing concretized
                #PARKED TOOL PORTION:
                #TODO PARKED: actually, we don't really care whether the time has become concrete. What we do care about is whether the feasibility sets are disjunct. (this can be tested with an intersection test) Preferably, we find a split where all t1 on one side and all t2 on the other side.
                #TODO PARKED: if we can find _some_ timing which occurs in one feasibility set but not in the other this may also be interesting on its own. (but harder to work with due to lack of proper feasibility set analysis)
                def testTiming(timingParam, solver, previousTimingCount = 100):
                    if solver.satisfiable():
                        timingNew = solver.eval(timingParam, previousTimingCount)
                        if len(timingNew) == 1:
                            print("timing concretized: %d" % timingNew[0])
                        elif len(timingNew) < previousTimingCount:
                            print("timing options limited. %d options left (%d options before)" % (len(timingNew), previousTimingCount))
                        else:
                            print("no changes in timing, continuing analysis")
                        return len(timingNew)
                    else:
                        return 0

                #create branches for each s
                ss = {}
                split = claripy.BVS("split",sec1.length) #k = split
                print("===============================================================")
                for r in relations:
                    print("testing split on relation %s..." % r)
                    if r == "__eq__":
                        sRk = (sec1 == split)
                        snRk = (sec2 != split)
                    elif r == "__ne__":
                        sRk = (sec1 != split)
                        snRk = (sec2 == split)
                    elif r == "SGE":
                        sRk = (sec1.SGE(split))
                        snRk = (sec2.SLT(split))
                    elif r == "SGT":
                        sRk = (sec1.SGT(split))
                        snRk = (sec2.SLE(split))
                    elif r == "UGE":
                        sRk = (sec1.UGE(split))
                        snRk = (sec2.ULT(split))
                    elif r == "UGT":
                        sRk = (sec1.UGT(split))
                        snRk = (sec2.SLE(split))
                    elif r == "__ge__":
                        sRk = (sec1.__ge__(split))
                        snRk = (sec2.__lt__(split))
                    elif r == "__gt__":
                        sRk = (sec1.__gt__(split))
                        snRk = (sec2.__le__(split))
                    elif r == "SLE":
                        sRk = (sec1.SLE(split))
                        snRk = (sec2.SGT(split))
                    elif r == "SLT":
                        sRk = (sec1.SLT(split))
                        snRk = (sec2.SGE(split))
                    elif r == "ULE":
                        sRk = (sec1.ULE(split))
                        snRk = (sec2.UGT(split))
                    elif r == "ULT":
                        sRk = (sec1.ULT(split))
                        snRk = (sec2.UGE(split))
                    elif r == "__le__":
                        sRk = (sec1.__le__(split))
                        snRk = (sec2.__gt__(split))
                    elif r == "__lt__":
                        sRk = (sec1.__lt__(split))
                        snRk = (sec2.__ge__(split))
                    ss.__setitem__(r,solver.branch())
                    ss[r].add(sRk) #s R k
                    ss[r].add(snRk) #s' !R k
                    print("testing time1...")
                    testTiming(time1, ss[r], len(timingsBefore))
                    print("testing time2...")
                    testTiming(time2, ss[r], len(timingsBefore))

                # 7: limit s and s' to edge cases near k (symbolically).
                # 8: see if t already concretized
                #DONE: actually, what we're doing here with the > and the +1 only works if sec can take on any value from a continues integer domain... if sec can take on, e.g., only even values, this approach doesn't work properly. We may want to do something with a +/-k and try to minimize k.
                #TODO: This will get us further; however, this again has its limitations, e.g., when gaps between values are nonconstant.
                print("===============================================================")
                for r in relations:
                    print("limiting secret to edge cases on %s..." % r)
                    if r == "__eq__" or r == "__ne__":
                        print("still unimplemented: define edge cases for (in)equality")
                    else: #< > edge cases are "simple"
                        minimumDistance = claripy.BVS("minimumDistance", sec1.length)
                        if (ss[r].satisfiable([sec1 == split])):
                            ss[r].add(sec1 == split)
                            tbranch = ss[r].branch()
                            if (ss[r].satisfiable([sec2.SGT(split)])): #SGT / UGT probably depends on r...
                                tbranch.add(sec2 == split+minimumDistance)
                                tbranch.add(minimumDistance>0) #redundant because s1 != s2 but that won't hurt
                                ss[r].add(sec2 == split+tbranch.min(minimumDistance))
                            else:
                                tbranch.add(sec2 == split-minimumDistance)
                                tbranch.add(minimumDistance>0) #redundant because s1 != s2 but that won't hurt
                                ss[r].add(sec2 == split-tbranch.min(minimumDistance))
                        else:
                            ss[r].add(sec2 == split)
                            tbranch = ss[r].branch()
                            if (ss[r].satisfiable([sec1.SGT(split)])):
                                tbranch.add(sec1 == split+minimumDistance)
                                tbranch.add(minimumDistance>0) #redundant because s1 != s2 but that won't hurt
                                ss[r].add(sec1 == split+tbranch.min(minimumDistance))
                            else:
                                tbranch.add(sec1 == split-minimumDistance)
                                tbranch.add(minimumDistance>0) #redundant because s1 != s2 but that won't hurt
                                ss[r].add(sec1 == split-tbranch.min(minimumDistance))
                    print("testing time1...")
                    testTiming(time1, ss[r], len(timingsBefore))
                    print("testing time2...")
                    testTiming(time2, ss[r], len(timingsBefore))

                print("===============================================================")

                # 9: find options for k (number of options for k is basically the accuracy of the side channel)
                #NOTE: (this doesn't scale well. we may want to do a self composition here again and find a k where k' = k+1, or k+n, and minimize n, to determine accuracy and determine whether this accuracy is constant or declines
                for r in relations:
                    print("identifying possible split values for relation %s" % r)
                    print(sorted(ss[r].eval(split,100)))
    print("===============================================================")
    import pluginTime
    if len(pluginTime.type1violations) > 0:
        t1violations = []
        for v in pluginTime.type1violations:
            t1violations.append("%s @ 0x%x" % (v[0], v[1]))
        print("type 1 violations: %s" % t1violations)
    if len(pluginTime.type2violations) > 0:
        t2violations = []
        for v in pluginTime.type2violations:
            t2violations.append("%s @ 0x%x" % (v[0], v[1]))
        print("type 2 violations: %s" % t2violations)
    print("===============================================================")
    import timingModel
    if len(timingModel.unmodeledInstructions) > 0:
        print("unmodeled instructions encountered during execution: %s" % timingModel.unmodeledInstructions)
        print("assumed %d cycle(s) issue time and %d cycle(s) result latency" % (settings.DEFAULTEXECUTIONTIME, settings.DEFAULTRESULTLATENCY))
    else:
        print("all instructions were successfully interpreted")
        
    print("---------------------------------------------------------------")
        
    #v 0: run code
    #v 1: freeup variables in each constraint to gain as limited relations s E k as possible.
    #v 2: duplicate constraints to C and C'
    #v 3: add s!=s', p==p', t!=t'
    #v 4: compute dynamic range.
    # 5: add s E k and s' !E k   ( limit k to max and min s, s'? (not sure if actually needed))
    # 6: see if t already concretized
    # 7: limit s and s' to edge cases near k (symbolically).
    #       -> edge cases:  for E is < >  etc, use minmax.
    #                       for E is = !=, add another C" and add t" = t, p" = p s" = s+q, then minimize q, possibly even another C"', where s"' = s+2q,  and t"' = t', p"' = p
    # 8: see if t already concretized
    # 9: find options for k (number of options for k is basically the accuracy of the side channel)
    # 10: concretize k
    # 11: see if t already concretized
    # 12: if t not yet concretized, concretize it ourselves. (is this actually a valid step? I think waiting for it to concretize is the only method we have to know that the relation applies to all t! (possibly this may only apply to some scenario's)) (one reason t might not concretize though is that k, pubs, or secrets, could be negative, and this makes the comparison still undeterministic at this point. Thus, it may be good to make sure only positive k's or p's are considered at this point.
    # 13: generate a public value to create this behavior.

    #of course we might as well just try different relations between s, s', and k directly without forming k ourselves... but that brings us a lot less close to a solution if we don't know what exactly the relation is in the actual program. current approach should give us more fine-grained control. A problem with a guessing approach is also that if you don't know that there is a s>=k relationship, you don't know whether s==k+1 and s'==k are actually edge cases

    #time cannot yet become concrete because a negative or zero public value messes with large secrets. (same for secrets... should probably be sure to check results when taking out edge cases such as negative values and zeroes.

    #TODO PARKED: how do we deal with multiple relations on s? should we treat them individually or holistically?
    #let's not worry about this right now
    #currently I'm extracting the relations sRk but only using the relation from that, throwing overboard the rest of the expression.
    #two import things should be noted here:
    #   we lose the constraints on k.
    #   we lose the actual "minimal" expression on s that we were able to form, which may not always be s itself.
    #       thus, we may want to replace k in sRk with split, and add a constraint that k == split.

    #NOTE: even if time doesn't become concrete it still shows that time depends on the secret (up to the limitations of the constraint solver of course)
    #this gives a good basis for further manual analysis


print("Total tool processing time: %0.1f seconds" % (TIMER.clock() - startTotalTime))

#c = store.insn

def r():
    store.tpg.errored[0].retry()
