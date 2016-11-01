import sys
filename = sys.argv[1]
f = open(filename,'r')
syscalls = {}
for line in f:
	if (line.count('(') == 0):
		continue
	else:
		call = line[:line.index('(')]
		if syscalls.has_key(call):
			syscalls[call] += 1
		else:
			syscalls[call] = 1

sorted = []
for key in syscalls:
	sorted.append((syscalls[key],key))

sorted.sort()
sorted = sorted[::-1]
for call in sorted:
	print call


