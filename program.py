import json
import sys


patternEntryPoints = []
patternSanitization = []
patternSensitive = []

entrypoints = []
sanitization = [] 
sensitive = []
query = []

patternFile = open("vulnPatterns.txt", "r")

i = 1

for line in patternFile:

	if i == 2:
		for j in line.rstrip().split(','):
			if j[1:] not in patternEntryPoints:
				patternEntryPoints.append(j[1:])
	if i == 3:
		for j in line.rstrip().split(','):
			if j not in patternSanitization:
				patternSanitization.append(j)
	if i == 4:
		for j in line.rstrip().split(','):
			if j not in patternSensitive:
				patternSensitive.append(j)
		i = -1
	i = i + 1

JSONslice = open(sys.argv[1], "r")
json_data = json.load(JSONslice)

for i in json_data['children']:

	#entryPoints
	if i['kind'] == "assign":
		if i['right'].has_key('what') and i['right']['what']['name'] in patternEntryPoints:
			#inserir na lista o entrypoint associado a variavel
			entrypoints.append([i['right']['what']['name'],i['left']['name']])

		#sanitization
		if i['right'].has_key('what') and i['right']['what']['name'] in patternSanitization:
			#inserir na lista o sanitization associado a variavel
			for j in i['right']['arguments']:
				sanitization.append([i['right']['what']['name'],j['name']])

		#query
		if i['right'].has_key('value'):
			query.append([i['left']['name']])
			for j in i['right']['value']:
				if j['kind'] == "variable":
					query[len(query)-1].append(j['name'])

		#sensitiveSinks
		if i['right'].has_key('what') and i['right']['what']['name'] in patternSensitive:
			#inserir na lista o sensitiveSink associado a variavel
			sensitive.append([i['right']['what']['name']])
			for j in i['right']['arguments']:
				sensitive[len(sensitive)-1].append(j['name'])

	#sensitiveSinks
	if i['kind'] == "call":
		#inserir na lista o sensitiveSink associado a variavel
			sensitive.append([i['what']['name']])
			for j in i['arguments']:
				sensitive[len(sensitive)-1].append(j['name'])

	


print(entrypoints)
print(sensitive)
print(query)

