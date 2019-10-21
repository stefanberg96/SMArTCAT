import claripy
import re
import selfComposition2

compTime = 0
copyTime = 0

class SelfComposition(selfComposition2.SelfComposition):
    """
    This class represents self-compositions of constraint sets
    It uses CDSet objects to represent constraint sets.
    
    constraintSets is a numbered dictionary containing all constraint set copies. This set is read only
    
    symbols is a two-dimensional dictionary[symbolName][constraintSetCopy] with names from the original constraint symbols, and the number of the    constraint set copy, mapping to the corresponding symbol in that copy.
    Unfortunately, the symbols approach prevents us from working on expressions over symbols directly, which may sometimes be convenient, such as when working on reversed symbols...
    TODO: implement a function to register expressions over variables
    
    composition is the composition of all constraint sets.
    """
    
    class SymbolManager(object):
        """
        This class is used as an easy interface to talk to groups of named symbols.
        It is initialized with a symbol descriptor and a composition, the symbol descriptor is used to search for symbols in the composition's symbol list so all can be accessed simultaneously.
        """
        def __init__(self, composition, descriptor):
            self.composition = composition
            self.descriptor = descriptor
            
        def matches(self, symbol):
            """
            determines whether the symbol matches the descriptor
            """
            return re.search(self.descriptor,symbol)
            
        def equal(self):
            """
            connects all symbols of the composition which match this managers description using an equals relation
            """
            if len(self.composition.constraintSets) == 2:
                for s in self.composition.symbols:
                    if (self.matches(s)):
                        self.composition.connect(self.composition.symbols[s][0] == self.composition.symbols[s][1])
            else:
                raise NotImplementedError("SymbolManager functions have not yet been implemented for self compositions over more than 2 copies")
                
        def unequal(self):
            """
            connects all symbols of the composition which match this managers description using an unequals relation
            """
            if len(self.composition.constraintSets) == 2:
                for s in self.composition.symbols:
                    if (self.matches(s)):
                        self.composition.connect(self.composition.symbols[s][0] != self.composition.symbols[s][1])
            else:
                raise NotImplementedError("SymbolManager functions have not yet been implemented for self compositions over more than 2 copies")
            
    
    def __init__(self, constraintSet, composeCount = 2):
        """
        composeCount determines the number of copies of the constraintSet in the composition. (0 returns an half-initialized composition object)
        This constructor creates a basic self composition which isn't yet connected by connector constraints. Use connect() to add auxiliary constraints over the symbols in symbols[symbolName][constraintSetCopy]
        TODO: het duplicaten van de public waardes is eigenlijk onnodig als we toch zeggen dat p=p'!
        
        before optimisation: self-composition preparation takes up total 5.6 seconds in testShiftedLoadARM
        """
        
        selfComposition2.SelfComposition.__init__(self)
        
        import time
        global copyTime
        startTime = time.clock()
        
        if composeCount > 0:
            self.constraintSets = {}
            
            self.symbols = {}
            #for s in constraintSet.symbols:
            #    self.symbols[s] = {}
                
            
            for c in range(0, composeCount):
                #create all constraintSets
                self.constraintSets[c] = constraintSet.copyUnique()
                #add the new constraintSet's symbols to the symbols dictionary
                for k in self.constraintSets[c].symbols:
                    if not self.symbols.__contains__(k):
                        self.symbols[k] = {}
                    self.symbols[k][c] = self.constraintSets[c].symbols[k]
                #create the composition of all constraints
                for cc in self.constraintSets[c].solver.constraints:
                    self.add(cc)
            self.composition = self.constraints
            
            self.publics = self.SymbolManager(self, "public*")
            self.secrets = self.SymbolManager(self, "secret*")
            
        deltaTime = time.clock() - startTime
        copyTime += deltaTime
        #print "performed self-composition preparation in %f seconds" % deltaTime
        #print "total time spent on self-composition preparation: %f seconds" % copyTime
            
    def satisfiable(self, extra_constraints=(), **kwargs):
        #before optimisation: self-composition satisfiability takes up total 2.2 seconds in testShiftedLoadARM
        import time
        global compTime
        startTime = time.clock()
        result = claripy.Solver.satisfiable(self, extra_constraints, **kwargs)
        deltaTime = time.clock() - startTime
        compTime += deltaTime
        #print "performed self-composition proof in %f seconds" % deltaTime
        #print "total time spent on self-composition proofs: %f seconds" % compTime
        
        return result
    
    def branch(self):
        copy = SelfComposition(None, 0)
        for c in self.constraints:
            copy.add(c)
        copy.constraintSets = self.constraintSets
        copy.symbols = self.symbols
        copy.composition = copy.constraints
        return copy
    
    def connect(self, constraint):
        """
        add constraints to the composition to connect the different copies
        note: newly introduced symbols aren't put in the symbols dictionary
        is currently just a shell for add(constraint) but may be extended to work easily with the symbol list
        """
        self.add(constraint)