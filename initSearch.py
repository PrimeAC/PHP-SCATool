
patternEntryPoints = []
paternSanitization = []
patternSensitive = []

i = 1

patternFile = open("vulnPatterns.txt", "r")

for line in patternFile:

	if i == 2:
		for j in line.rstrip().split(','):
			if j[1:] not in patternEntryPoints:
				patternEntryPoints.append(j[1:])
	if i == 3:
		for j in line.rstrip().split(','):
			if j not in paternSanitization:
				paternSanitization.append(j)
	if i == 4:
		for j in line.rstrip().split(','):
			if j not in patternSensitive:
				patternSensitive.append(j)
		i = -1
	i = i + 1

