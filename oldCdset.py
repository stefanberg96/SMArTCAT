import analysisUtils
import claripy
nonce = 0

def CDSet_from_state(state, symbol, symbols = None):
    return CDSet(state.se._stored_solver, symbol, symbols)

class CDSet(object):
    """
    This class defines constrained-defined sets. They operate on symbolic values and constraint solvers.
    a CDSet is generated from an engine's state at the point of CDSet initialization, later changes to the engine's state do not affect the CDSet
    
    This class is gaining more of a function for other analysis on constraints such as self-composition analysis
    
    TODO: implement feasible set as seperate constraints (set structure / auxiliary constraints, which are treated differently than normal constraints)
    
    CDSet.symbols is a mapping from the names of symbols to the actual symbolic values.
    a unique copy maintains the names of the symbols but creates new symbolic values internally.
    """
    
    def __init__(self, solver, symbol, symbols = None):
        self.solver = solver.branch()
        self.symbol = symbol
        self.symbolName = list(symbol.variables)[0]
        if (symbols == None):
            self.symbols = analysisUtils.uniqueSymbols(solver.constraints)
        else:
            self.symbols = symbols
        
    def copy(self):
        """
        simple copy function, symbol names don't change
        """
        return CDSet(self.solver, self.symbol, self.symbols)
        
    def constrain(self, constraint):
        """
        add constraint to the set of constraints limiting this set
        TODO: make sure new symbols are added to the symbol list
        """
        self.solver.add(constraint)
        
    def solve(self, maxSolutions):
        """
        returns at most maxSolutions of values contained in this set
        """
        return self.solver.eval(self.symbol, maxSolutions)
        
    def intersect(self, otherCDSet):
        """
        intersection of state spaces
        """
        otherCopy = otherCDSet.copyUnique()
        
        intersectionSymbol = claripy.BVS('intersection_(%s,%s)' % (self.symbolName,otherCopy.symbolName), self.symbol.length)
        resultSolver = self.solver.branch()
        resultSolver.add(otherCopy.solver.constraints)
        resultSolver.add(intersectionSymbol == self.symbol)
        resultSolver.add(intersectionSymbol == otherCopy.symbol)
        
        return CDSet(resultSolver, intersectionSymbol)
        
    def union(self, otherCDSet):
        """
        union of state spaces
        """
        otherCopy = otherCDSet.copyUnique()
        
        unionSymbol = claripy.BVS('union_(%s,%s)' % (self.symbolName,otherCopy.symbolName), self.symbol.length)
        resultSolver = self.solver.branch()
        resultSolver.add(otherCopy.solver.constraints)
        resultSolver.add(claripy.Or(unionSymbol == self.symbol, unionSymbol == otherCopy.symbol))
        
        return CDSet(resultSolver, unionSymbol)
        
    """
    #complement this set (complement of the constraints over this set's symbol)
    #returns a new set with a new symbol
    def complement(self):
        \"""
        complement of state space
        \"""
        resultSolver = self.solver.blank_copy()
        
        originalConstraints = claripy.true
        for c in self.solver.constraints:
            if c.variables.__contains__(self.symbolName):
                originalConstraints = claripy.And(originalConstraints, c)
            else:
                resultSolver.add(c)
        resultSolver.add(claripy.Not(originalConstraints))
        return CDSet(resultSolver, self.symbol)
        
        return CDSet(resultSolver, complementSymbol)
    
    #this only generates complement constraints, don't forget to also add the original constraints
    def complementRecursive(self, expression, complementConstraintSet=None, complementingDict=None):
    
        def complementExpression(expression):
            if c.op == 'BVS':
                if not complementingDict.__contains__(c.args[0]):
                    complementingDict[c.args[0]] = claripy.BVS("complement(%s)" % c.args[0])
                return complementingDict[c.args[0]]
            else if c.op == 'And': 
                cArgs = [];
                for a in c.args:
                    cArgs.append(complementRecursive(a))
                return claripy.Or(*cArgs)
            else if c.op == 'Or': 
                cArgs = [];
                for a in c.args:
                    cArgs.append(complementRecursive(a))
                return claripy.And(*cArgs)
            else if c.op == "ULE" or c.op == "__le__": # unsigned <=
                return claripy.UGT(complementRecursive(c.arg[0]), self.solver.max(c.arg[1]))
            else if c.op == "ULT" or c.op == "__lt__": # unsigned <=
                return claripy.UGE(complementRecursive(c.arg[0]), self.solver.max(c.arg[1]))
            else if c.op == "UGE" or c.op == "__ge__": # unsigned <=
                return claripy.ULT(complementRecursive(c.arg[0]), self.solver.max(c.arg[1]))
            else if c.op == "UGT" or c.op == "__gt__": # unsigned <=
                return claripy.ULE(complementRecursive(c.arg[0]), self.solver.max(c.arg[1]))
            
                
                    
        #ast.op to find operation
        #ast.args to find arguments.
        if complementConstraintSet == None:
            complementConstraintSet = []
        if complementingDict == None:
            complementingDict = {}
        complementedConstraints = []
        for c in self.solver.constraints:
            complementedConstraints.append(complementExpression(c))
        if len(complementedConstraints) > 1:
            return claripy.Or(*complementedConstraints)
        else:
            return complementedConstraints[0]
    """
    
    
 
    def cardinality(maxCardinality=2):
        """
        Attempts to find the cardinality of this set
        usually differentiates between 0,1,2 or more, and the universal set of the feasible domain
        
        if maxCardinality is provided, this function attempts to find exact cardinality upto maxCardinality, or if maxCardinality is returned the cardinality is maxCardinality or larger.
        """
        guess = len(self.solve(maxCardinality))
        return guess
        
    
    def copyUnique(self):
        """
        sets will often contain variables with equal names; we need to make them unique to prevent constraints from interacting.
        the symbols dictionary of the copy will maintain a mapping from the old names to the new symbols
        TODO, FIXME: THIS INSTRUCTION IS VERY INEFFICIENT!!
        """
        global nonce
        se2 = self.solver.blank_copy()
        symbol2 = claripy.BVS("%s_u%d" % (self.symbolName, nonce), self.symbol.length)
        replacementDict = {self.symbolName : (self.symbol, symbol2)} # dict from old var names to (old var BVS, new var BVS) tuples
        for c in self.solver.constraints:
            c2 = c.replace_dict({})
            for v in c.variables:
                if not replacementDict.__contains__(v):
                    oldvar = analysisUtils.stringToVar(v, self.solver.constraints)
                    #this function can currently only copy BVS and BoolS type symbols.
                    #TODO: implemnt FPS as well
                    if isinstance(oldvar, claripy.ast.bv.BV):
                        replacementDict[v] = (oldvar, claripy.BVS("%s_u%d" % (v,nonce), oldvar.length))
                        #elif isinstance(oldvar, claripy.ast.bool.Bool):
                        #    replacementDict[v] = (oldvar, claripy.BoolS("%s_u%d" % (v,nonce)))
                    else:
                        raise NotImplementedError("unique constraintset copying doesn't yet support copying symbols of type %d" % type(oldvar))
                c2 = c2.replace(replacementDict[v][0], replacementDict[v][1])
            se2.add(c2)
        nonce += 1
        #create the new symbols list which maps old var names to new symbols
        newSymbols = {}
        for k in replacementDict:
            newSymbols[k] = replacementDict[k][1]
        return CDSet(se2,replacementDict[self.symbolName][1],newSymbols)