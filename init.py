"""
Initialize the tool framework by injection our functions into angr.
"""
from __future__ import print_function

def init():
    print("\n======================= Initialising ========================\n")    
    import pyvex
    import angr
    import pluginTime
    from platforms.angr_platforms import risc_v
    print("Initialized execution time plugin")
    import metaPlugin
    print("Initialized meta-state plugin")
    injectPipelineIntoIMark()
    print("Initialized symbolic pipeline processor")
    injectSelfCompositionSolver()
    print("Initialized self-composition solver")
    
    import settings
    if not settings.MODEL_CACHE_CHANNELS:
        print("Cache channel analysis is turned off")
    else:
        print("Cache channel analysis is turned on")
    
    if not settings.MODEL_BRANCH_CHANNELS:
        print("Branch-predictor-based channel analysis is turned off")
    else:
        print("Branch-predictor-based channel analysis is turned on")
    
    if settings.OUTPUT_VEX:
        lifterOutputVex()
    
    import store
    store.b = angr.Project(settings.TARGET_BINARY)
    store.b.arch.capstone.detail=True #set this so we have access to instruction details required for our timing model
    store.b.factory.default_engine._default_opt_level = 0
    print("Loaded binary %s" % settings.TARGET_BINARY)

    #apply the skips from the settings using user hooks
    for (from_address, to_address) in settings.skips:
        def skip(state):
            print('Skipping at {:x} till {:x}({:d} bytes)'.format(from_address, to_address, to_address-from_address))
        store.b.hook(from_address, skip, to_address-from_address)
    
    import resource
    soft,hard = resource.getrlimit(resource.RLIMIT_AS)  #determine current limit
    resource.setrlimit(resource.RLIMIT_AS, (1024*1024*1024*settings.MAX_MEM, hard)) #update limit
    print("Max memory consumption set to %d GB" % settings.MAX_MEM)

    

def injectSelfCompositionSolver():
    from angr.state_plugins.solver import SimSolver
    from selfComposition import SelfComposition
    #inject selfCompositionSolver as solver
    oldInit = SimSolver.__init__
    def newInit(_self, solver=None):
        if solver == None:
            solver = SelfComposition()
        return oldInit(_self, solver)
    SimSolver.__init__ = newInit
    
def injectPipelineIntoIMark():
    import angr
    import pipelineModel
    #_expressions = simuvex.engines.vex.expressions
    oldExec = angr.engines.vex.statements.imark.SimIRStmt_IMark
    def newExec(_self, state, stmt):
        pipelineModel.computePipelineTime(_self, state, stmt)
        return oldExec(_self, state, stmt)
    angr.engines.vex.statements.imark.SimIRStmt_IMark = newExec
    angr.engines.vex.statements.STMT_CLASSES[1] = newExec
    
def lifterOutputVex():    
    #monkey patch to output vex statements
    from pyvex.lift import Lifter
    oldpostprocess = Lifter.postprocess
    def lifterPostProcess(_self):
        _self.irsb.pp()
        return oldpostprocess(_self);
    Lifter.postprocess = lifterPostProcess
