
entryPoints = []
sanitization = []
sensitive = []

i = 1

patternFile = open("vulnPatterns.txt", "r")

for line in patternFile:

	if i == 2:
		for j in line.rstrip().split(','):
			if j[1:] not in entryPoints:
				entryPoints.append(j[1:])
		print entryPoints 
	if i == 3:
		for j in line.rstrip().split(','):
			if j not in sanitization:
				sanitization.append(j)
		print sanitization
	if i == 4:
		for j in line.rstrip().split(','):
			if j not in sensitive:
				sensitive.append(j)
		print sensitive
		i = -1
	i = i + 1

