import os

i = 1

while i < 12:
	print "SLICE " + str(i) + ":"
	os.system("python ./program.py proj-slices/slice" + str(i) + ".json")
	i = i + 1 
	