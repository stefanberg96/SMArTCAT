from __future__ import print_function
import claripy
import cdset
import analysisUtils as u

#define public, secret, and time symbols:
p1 = claripy.BVS("p1", 8)
s1 = claripy.BVS("s1", 8)
t1 = claripy.BVS("t1", 8)
p2 = claripy.BVS("p2", 8)
s2 = claripy.BVS("s2", 8)
t2 = claripy.BVS("t2", 8)
p3 = claripy.BVS("p3", 8)
s3 = claripy.BVS("s3", 8)
t3 = claripy.BVS("t3", 8)

#create the constraint which defines the relationship between p,s, and t.
#they are all the same because this is a self composed program.
#normally this relationship would be expressed more complexly than with a simple if statement.
C1 = claripy.Solver()
C2 = claripy.Solver()
C3 = claripy.Solver()
C1.add(t1 == claripy.If(s1%p1==0, claripy.BVV(99,8), claripy.BVV(1,8)))
C2.add(t2 == claripy.If(s2%p2==0, claripy.BVV(99,8), claripy.BVV(1,8)))
C3.add(t3 == claripy.If(s3%p3==0, claripy.BVV(99,8), claripy.BVV(1,8)))

#compose the constraints for analysis
sol = claripy.Solver()
sol.add(C1.constraints)
sol.add(C2.constraints)
sol.add(C3.constraints)

#create the relationship between the constraint copies
#p1 == p2 == p3
sol.add(p1 == p2)
sol.add(p1 == p3)
#s1 != s2 != s3
sol.add(s1 != s2)
sol.add(s2 != s3)
sol.add(s1 != s3)
#t1 == t3 != t2
sol.add(t1 != t2)
sol.add(t1 == t3)
#s1 < s2 < s3
sol.add(s1 < s2)
sol.add(s2 < s3)

assert(len(sol.eval(t1,2)) > 1)
#time hasn't concretized yet

#s3 = s1+2 (thus s2 = s1+1)
sol.add(s3 == s1+2)

assert(len(sol.eval(t1,2)) > 1)
#time hasn't concretized yet

#concretize time ourselves:
sol.add(t1 == 99)

assert(len(sol.eval(p1,2)) == 1)
assert(sol.eval(p1,2)[0] == 2)
#public value has concretized to 2. thus: given p = 2, there exists atleast one combination of s1 < s2 < s3, s3=s1+2, for which the time implies whether the secret is s2 or another secret.

print("secret1: %s; len: %s" % (sorted(sol.eval(s1,300)), len(sol.eval(s1,300))))
print("secret2: %s; len: %s" % (sorted(sol.eval(s3,300)), len(sol.eval(s3,300))))
print("secret3: %s; len: %s" % (sorted(sol.eval(s2,300)), len(sol.eval(s2,300))))

#in this specific case we see that for all combinations of s1 < s2 < s3 where s3=s1+2, if p1 == 2, time will imply the secret's parity.
#using a binary search choosing different p on each run will reveal the entire secret.
#however, we can't look at all possible values for s like we just did above if the feasibility space is large.
#thus, we can only apply above solution if we know that a s%f(p) --> t relationship exists for some function f over p.