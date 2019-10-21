import angr
proj = angr.Project('/home/stefan/rasp/arm_files/test')
start = 0x0001051c
end = 0x10588
avoid = 0x105090
state = proj.factory.blank_state(addr=start, save_unsat = True)
a = state.regs.r0
b = state.regs.r1
state.solver.add(a<20)
state.solver.add(b<20)
sm = proj.factory.simulation_manager(state)
while len(sm.active) > 0:
    print(sm)
    sm.explore(avoid= avoid, find=end, n=1)
    if len(sm.found) > 0:
        state=sm.found[0]
        print(sm.unsat)
        print("a = "+ str(state.se.eval_upto(a,10)))
        break;
        
