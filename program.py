import json
import sys


patternEntryPoints = {}
patternSanitization = {}
patternSensitive = {}

entrypoints = {}
sanitization = {} 
sensitive = {}
query = {}

patternFile = open("vulnPatterns.txt", "r")

i = 1
name = ""
for line in patternFile:
	if i == 1:
		name = line.rstrip()
		if name not in patternEntryPoints.keys():
			patternEntryPoints.update({name:[]})
		if name not in patternSanitization.keys():
			patternSanitization.update({name:[]})
		if name not in patternSensitive.keys():	
			patternSensitive.update({name:[]})

	if i == 2:
		for j in line.rstrip().split(','):
			if j[1:] not in patternEntryPoints.get(name):
				patternEntryPoints[name].append(j[1:])
	if i == 3:
		for j in line.rstrip().split(','):
			if j not in patternSanitization.get(name):
				patternSanitization[name].append(j)
	if i == 4:
		for j in line.rstrip().split(','):
			if j not in patternSensitive.get(name):
				patternSensitive[name].append(j)
		i = -1
	i = i + 1

JSONslice = open(sys.argv[1], "r")
json_data = json.load(JSONslice)

print patternEntryPoints
print patternSanitization
print patternSensitive

for i in json_data['children']:

	if i['kind'] == "assign": #assign

		if i['right']['kind'] == "offsetlookup": #assign -> offsetlookup

			entrypoints[i['left']['name']] = i['right']['what']['name']

		if i['right']['kind'] == "encapsed": #assign -> encapsed
			query[i['left']['name']] = []
			
			for j in i['right']['value']:
				
				if j['kind'] == "variable":
					query[i['left']['name']].append(j['name'])

		if i['right']['kind'] == "bin": #assign -> bin
			query[i['left']['name']] = []
			
			if i['right']['left']['kind'] == "variable":
				query[i['left']['name']].append(i['right']['left']['name'])

			if i['right']['right']['kind'] == "variable":
				query[i['left']['name']].append(i['right']['right']['name'])


		if i['right']['kind'] == "call": #assign -> call
			sensitive[i['right']['what']['name']] = []
 
			for j in i['right']['arguments']:

				if j['kind'] == "variable":
					sensitive[i['right']['what']['name']].append(j['name'])

	if i['kind'] == "call": #call
		sensitive[i['what']['name']] = []

		for j in i['arguments']:
			if j['kind'] == "variable":
				sensitive[i['what']['name']].append(j['name'])

	if i['kind'] == "echo": #echo
		entrypoints[i['kind']] = i['arguments'][0]['what']['name']


	if i['kind'] == "while": #while
		
		if i['body']: #while -> body
			#print "ESTOU NO BODY"
			for j in i['body']['children']:
				#print j

				if j['kind'] == "assign": #assign

					if j['right']['kind'] == "offsetlookup": #assign -> offsetlookup

						#entrypoints.append([i['right']['what']['name'], i['left']['name']])
						entrypoints[j['left']['name']] = j['right']['what']['name']

					if j['right']['kind'] == "encapsed": #assign -> encapsed
						#query.append([i['left']['name']])
						query[j['left']['name']] = []
						
						for k in j['right']['value']:
							
							if k['kind'] == "variable":
								#query[len(query)-1].append(j['name'])
								query[j['left']['name']].append(k['name'])

					if j['right']['kind'] == "bin": #assign -> bin
						#query.append([i['left']['name']])
						query[j['left']['name']] = []
						
						if j['right']['left']['kind'] == "variable":
							#query[len(query)-1].append(i['right']['left']['name'])
							query[j['left']['name']].append(j['right']['left']['name'])

						if j['right']['right']['kind'] == "variable":
							query[j['left']['name']].append(j['right']['right']['name'])


					if j['right']['kind'] == "call": #assign -> call
						#sensitive.append([i['right']['what']['name']])
						sensitive[j['right']['what']['name']] = []
			 
						for k in j['right']['arguments']:

							if k['kind'] == "variable":
								#sensitive[len(sensitive)-1].append(j['name'])
								sensitive[j['right']['what']['name']].append(k['name'])

					if j['right']['kind'] == "variable": #assign -> variable
						query[j['left']['name']] = [j['right']['name']]
						

						

	if i['kind'] == "if": #if

		if i['body']['children'][0]['kind'] == "assign":
			query[i['body']['children'][0]['left']['name']] = []
			
			if i['body']['children'][0]['right']['kind'] == "encapsed":

				for j in i['body']['children'][0]['right']['value']:

					if j['kind'] == "variable":
						query[i['body']['children'][0]['left']['name']].append(j['name'])

			if i['alternate']['children'][0]['right']['kind'] == "encapsed":
				
				for j in i['alternate']['children'][0]['right']['value']:

					if j['kind'] == "variable":
						query[i['alternate']['children'][0]['left']['name']].append(j['name'])



print(entrypoints)
print(sensitive)
print(query)

for key, value in sensitive.items():
	if len(value) > 1:
		for i in value:
			if i in query.keys():
				if len(query.get(i)) > 1:
					for j in query.get(i):
						if j in entrypoints.keys():
							print "Vulnerable!"
				else:
					if query.get(i)[0] in entrypoints.keys():
						print "Vulnerable!"
	else:
		for i in value:
			if i in query.keys():
				if len(query.get(i)) > 1:
					for j in query.get(i):
						if j in entrypoints.keys():
							print "Vulnerable!"
				else:
					if query.get(i)[0] in entrypoints.keys():
						print "Vulnerable!"

