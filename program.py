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

	if i['kind'] == "assign": #assign

		if i['right']['kind'] == "offsetlookup": #assign -> offsetlookup

			entrypoints.append([i['right']['what']['name'], i['left']['name']])

		if i['right']['kind'] == "encapsed": #assign -> encapsed
			query.append([i['left']['name']])
			
			for j in i['right']['value']:
				
				if j['kind'] == "variable":
					query[len(query)-1].append(j['name'])

		if i['right']['kind'] == "bin": #assign -> bin
			query.append([i['left']['name']])
			
			if i['right']['left']['kind'] == "variable":
				query[len(query)-1].append(i['right']['left']['name'])

			if i['right']['right']['kind'] == "variable":
				query[len(query)-1].append(i['right']['right']['name'])


		if i['right']['kind'] == "call": #assign -> call
			sensitive.append([i['right']['what']['name']])
			
			for j in i['right']['arguments']:

				if j['kind'] == "variable":
					sensitive[len(sensitive)-1].append(j['name'])

	if i['kind'] == "call": #call
		sensitive.append([i['what']['name']])
		for j in i['arguments']:
			if j['kind'] == "variable":
				sensitive[len(sensitive)-1].append(j['name'])

	if i['kind'] == "echo": #echo
		entrypoints.append([i['arguments'][0]['what']['name'], i['kind']])


print(entrypoints)
print(sensitive)
print(query)

