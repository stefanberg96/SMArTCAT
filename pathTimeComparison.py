
#analyses a path group's deadended paths
class TimeAnalysis(object):
    #__init__():
        

    # return a list containging, for each path, a list of achievable execution times
    def possibleTimes(self, pg):
        timingList = []
        for i,p in enumerate(pg.deadended):
            timingList.append(pathTime(p))
        return timingList
            
    # return a list with possible execution times for this path
    # maxLength is the maximum length of the returned list that will be computed
    # TODO: big bug: this currently evaluates constraints using the latest state, but constraints on timing at a certain point should of course be evaluated with the constraints of THAT state. either concretize immediately (possibly branch on multiple concretizations), copy constraints uniquely, or remember old states in timing plugin
    def pathTime(self, p, maxLength=10):
        return p.state.se.eval(p.state.time.totalExecutionTime, maxLength)

    # counts unique timings in a tuple, or list of tuples.
    # we assume we don't receive an empty list.
    def countUniqueTimings(self, times):
        foundTimes = set([])
        if isinstance(times[0],tuple):
            # it's a list of tuples
            for t in times:
                foundTimes = foundTimes.union(set(t))
            return len(foundTimes)
        else:
            return len(set(times))