import json
import sys


patterns = []

tainted = {}

entrypoints = {}
sanitization = {} 
sensitive = {}
query = {}

def assign(i):
	if i['right']['kind'] == "offsetlookup": #assign -> offsetlookup

			entrypoints[i['left']['name']] = i['right']['what']['name']
			tainted[i['left']['name']] = isTainted(i['right']['what']['name'])

	if i['right']['kind'] == "encapsed": #assign -> encapsed
		query[i['left']['name']] = []
		
		for j in i['right']['value']:
			
			if j['kind'] == "variable":
				query[i['left']['name']].append(j['name'])

				if isTainted(j['name']):
					tainted[i['left']['name']] = True

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

				if isTainted(j['name']):

					if getType(i['right']['what']['name']) == 2: #sanitization
						tainted[i['left']['name']] = False

	if i['right']['kind'] == "variable": #assign -> variable
		query[i['left']['name']] = [i['right']['name']]


def isIf(i):
	if i['body']['children'][0]['kind'] == "assign":
		query[i['body']['children'][0]['left']['name']] = []
		
		if i['body']['children'][0]['right']['kind'] == "encapsed":
			for j in i['body']['children'][0]['right']['value']:

				if j['kind'] == "variable":
					query[i['body']['children'][0]['left']['name']].append(j['name'])

		if i['alternate']:
			isIf(i['alternate'])


patternFile = open("vulnPatterns.txt", "r")

def isTainted(var):

	if tainted.has_key(var):
		return True

	else:
		return isMatch(var)

def getType(value):

	for group in patterns:

		for line in group:

			for field in line:

				if field == value:
					return group.index(line)

def isMatch(value):
	
	for group in patterns:

		for line in group:

			for field in line:

				if field == value:

					return True

	return False

i = 1
name = ""
aux = []
for line in patternFile:
	if i == 1:
		name = line.rstrip()
		aux.append([name])
	if i == 2:
		aux2 = []
		for j in line.rstrip().split(','):
			aux2.append(j[1:])
		aux.append(aux2)
	if i == 3:
		aux2 = []
		for j in line.rstrip().split(','):
			aux2 = []
			aux2.append(j)
		aux.append(aux2)
	if i == 4:
		aux2 = []
		for j in line.rstrip().split(','):
			aux2.append(j)
		aux.append(aux2)
		patterns.append(aux)
		aux = []
		i = -1
	i = i + 1

JSONslice = open(sys.argv[1], "r")
json_data = json.load(JSONslice)

for i in json_data['children']:

	if i['kind'] == "assign": #assign
		assign(i)
		
	if i['kind'] == "call": #call
		sensitive[i['what']['name']] = []

		for j in i['arguments']:
			if j['kind'] == "variable":
				sensitive[i['what']['name']].append(j['name'])

	if i['kind'] == "echo": #echo
		entrypoints[i['kind']] = i['arguments'][0]['what']['name']


	if i['kind'] == "while": #while
		
		if i['body']: #while -> body
			for j in i['body']['children']:
				if j['kind'] == "assign": #assign
					assign(j)

				if j['kind'] == "if": #if
					isIf(j)

						

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
print(tainted)