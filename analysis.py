from __future__ import print_function
import angr, claripy, simuvex

#def test_inspect(state):
#	print "++++++++++++++++ inspecting: 0x%08x ++++++++++++++" % state.inspect.instruction
		
class MockAnalysis(angr.Analysis):
	def __init__(self, maxDepth, verbose):
		self.maxDepth = maxDepth
		self.verbose = verbose
		self.instructionList = []
		
	def analyse(self):
		self.s = b.factory.entry_state()
#		self.s.inspect.b('instruction', when=simuvex.BP_BEFORE, action=test_inspect)
		p = b.factory.path(self.s)
		self.stepPathRecursively(p, 0, 0)
		print("")
		print("")
		print("")
		print("analysis finished")
		print("")
		print("")
		print(self.instructionList)
				
	def stepPathRecursively(self, path, depth, timeSoFar):
		if depth < self.maxDepth:
			if (self.verbose):
				print(" ")
				print(" ")
				print(" ")
				print("step %d; addr 0x%08x" % (depth, path.addr))
			#just add a last path for easy manual labor in python
			self.lastPath = path
			print("-----------------------------------------------")
			b.factory.block(path.addr).pp()
			print("---------------------------------------")
			b.factory.block(path.addr, opt_level=0).vex.pp()
			print("---------------------------------------")
			
			
			timeSoFar = self.walkOverStatements(path.addr, timeSoFar)
			
			print("---------------------------------------")
			path.step(opt_level=0)
			#step by instruction?
			if len(path.successors) > 0:
				if len(path.successors) != 1:
					print("branching: %d paths ahead" % len(path.successors))
				for p in path.successors:
					self.stepPathRecursively(p, depth+1, timeSoFar)
			else:
				print("path ended at depth %d. execution time: %d cycles" % (depth, timeSoFar))
		else:
			print("path stopped, maxdepth reached. execution time: %d cycles" % timeSoFar)
	
	def walkOverStatements(self, address, timeSoFar):
		block = b.factory.block(address, opt_level=0)
		for stmt in block.vex.statements:
			if stmt.tag == 'Ist_IMark':
				mnemonic = b.factory.block(stmt.addr+stmt.delta).capstone.insns[0].mnemonic
				if not mnemonic in self.instructionList:
					self.instructionList += [mnemonic]
				tte = timingModel(mnemonic)
				timeSoFar += tte
				if (self.verbose):
					print("---- Processing \"%s\" at address 0x%08x: ----" % (mnemonic, stmt.addr))
					print("time to execute: %d" % tte)
					print("cumulative time in this path: %d" % timeSoFar)
		return timeSoFar
			
def testHooking(state):
	mnemonic = b.factory.block(state.se.any_int(state.ip)).capstone.insns[0].mnemonic
	tte = timingModel(mnemonic)
	print("Hooked instruction: %s; %d cycles; address: 0x%08x" % (mnemonic, tte, state.se.any_int(state.ip)))
				
def timingModel(instruction):
	return {
		'add': 1,
		'mov': 2,
	}.get(instruction,0)
		
		
angr.register_analysis(MockAnalysis, 'MockAnalysis')

#b = angr.Project("/bin/true")
b = angr.Project("/home/roeland/Documents/programs/fauxware/fauxware")
#b.hook(b.entry, testHooking)
#b = angr.Project("/home/roeland/Documents/programs/test1/a.out")
mock = b.analyses.MockAnalysis(500, True)
mock.analyse()