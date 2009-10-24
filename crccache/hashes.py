#!/usr/bin/python

for N in (20,40):
	for S in (1024,102400,1024000):
		X=N*S*(1.0-1.0/N)
		for H in (16,24,30,32,48,60,64):
			R = (2**H)/X
			print "N=%d, S=%d, H=%d, 1 in %f" % (N,S,H,R)

