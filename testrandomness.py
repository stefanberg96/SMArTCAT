from __future__ import print_function
a = 838321080
def rand():
    global a
    bit = (((a >> 8) ^ (a>>4)) & 1)
    a = ((a << 1) | bit) & 0x1ff
    return bit
    
def test():
    for seed in [838321080, 808988721, 825374520, 808596788]:
        global a
        a = seed
        rand()
        start = a
        rand()
        i=2
        while start != a:
            i+=1
            rand()
        print("period: %d" % i)