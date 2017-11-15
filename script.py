import os

i = 1

while i < 12:
	os.system("python ./program.py proj-slices/slice" + str(i) + ".json")
	i = i + 1 
	