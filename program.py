import json
import sys

patterns = []

tainted = {}
conditional = {}
entrypoints = {}
query = {}

sanitization = None
paragraph = [] 
conditionalFlag = 0
conditionalIterator = 0


def checkSanitization(sink):
	if paragraph != []:
		checkSpecificPattern(sink)
	else:
		checkVulnerability(False, ["entry point does not match with sensitive sink"])

def checkVulnerability(vulnerable, info):
	temp = ""
	if vulnerable == True:
		print "> Program is vulnerable!"
		print "> Type of vulnerability: " + info[0]
		lenght = len(info[1])
		print "> Possible correction(s): "
		while lenght > 1:
			temp = temp + info[1][lenght-1] + ", "
			lenght = lenght - 1
		temp = temp + info[1][lenght-1]
		print temp
		sys.exit(0)

	else:
		print "> Program is not vulnerable!"
		print "> Due to: " + info[0]
		sys.exit(0)

def checkSpecificPattern(sink):
	for entry in entrypoints:
		i = -1
		for paragraphs in paragraph:	
			i = i + 1
			if entrypoints[entry] in patterns[paragraphs][1]:
				if sink in patterns[paragraphs][3]:
					checkVulnerability(False, [sanitization])  #false due to valid sanitization for entry and sink
				
				elif i == len(paragraph) - 1:
					checkVulnerability(False, ["sink used is not valid"])
				
			elif sink in patterns[paragraphs][3]:
				checkVulnerability(False, ["entry point used is not valid"]) 
			
			else:  #vulnerable
				checkAllPatterns(sink)

def checkAllPatterns(sink):

	for entry in entrypoints:
		i = 0
		for pattern in patterns:

			if entrypoints[entry] in pattern[1] and sink in pattern[3]:
				checkVulnerability(True, [patterns[i][0][0], patterns[i][2]])
			i = i +1

		checkVulnerability(False, ["entry point does not match with sensitive sink"])

def conditionalEngine(i, taint):
	if taint:
		if conditional.has_key(i['left']['name']):
			if len(conditional[i['left']['name']]) <= conditionalIterator:
				conditional[i['left']['name']].append(True)
			else:
				conditional[i['left']['name']][conditionalIterator] = True
		
		else:
			conditional[i['left']['name']] = []
			conditional[i['left']['name']].append(True)
				 
	else:
		if conditional.has_key(i['left']['name']):
			if len(conditional[i['left']['name']]) <= conditionalIterator:
				conditional[i['left']['name']].append(False)
			else:
				conditional[i['left']['name']][conditionalIterator] = False
		else:
			conditional[i['left']['name']] = []
			conditional[i['left']['name']].append(False)

def isAssign(i):
	if i['right']['kind'] == "offsetlookup": #assign -> offsetlookup

			entrypoints[i['left']['name']] = i['right']['what']['name']
			tainted[i['left']['name']] = isTainted(i['right']['what']['name'])

	if i['right']['kind'] == "encapsed": #assign -> encapsed
		query[i['left']['name']] = []
		
		for j in i['right']['value']:
			
			if j['kind'] == "variable":
				query[i['left']['name']].append(j['name'])
				
				if isTainted(j['name']):
					
					if conditionalFlag == 1:
						conditionalEngine(i, True) 
						break
					else:
						tainted[i['left']['name']] = True
						break

				else:

					if conditionalFlag == 1:
						conditionalEngine(i, False)
						break

					else:
						tainted[i['left']['name']] = False
			

	if i['right']['kind'] == "bin": #assign -> bin
		query[i['left']['name']] = []
		
		if i['right']['left']['kind'] == "variable":
			query[i['left']['name']].append(i['right']['left']['name'])

			if isTainted(i['right']['left']['name']):
				tainted[i['left']['name']] = tainted[i['right']['left']['name']]

		if i['right']['right']['kind'] == "variable":
			query[i['left']['name']].append(i['right']['right']['name'])

			if isTainted(i['right']['right']['name']):
				tainted[i['left']['name']] = tainted[i['right']['right']['name']]


	if i['right']['kind'] == "call": #assign -> call
		
		if conditionalFlag == 1:
			conditionalEngine(i, call(i['right']))
		else:
			#new implementation
			tainted[i['left']['name']] = call(i['right'])

		recursiveVariables(i['left']['name'])

	if i['right']['kind'] == "variable": #assign -> variable
		query[i['left']['name']] = [i['right']['name']]
		if isTainted(i['right']['name']) and conditionalFlag == 0 and tainted.has_key(i['left']['name']) == False:
			tainted[i['left']['name']] = True
			recursiveVariables(i['left']['name'])
		elif conditionalFlag == 0 and tainted.has_key(i['left']['name']) == False:
			tainted[i['left']['name']] = False


def isIf(i, recursion):
	global conditionalIterator

	for line in i['body']['children']:
		if line['kind'] == "assign":
			isAssign(line)

		if line['kind'] == 'call':
			call(line)
	
	conditionalIterator = conditionalIterator +1

	if recursion == True:
		if i['alternate']:
			isIf(i['alternate'], True)

	else:

		for line in i['alternate']['children']:
			if line['kind'] == "assign":
				isAssign(line)

			if line['kind'] == 'call':
				call(line)
	

def call(i):
	global paragraph
	global sanitization

	for j in i['arguments']:
		
		if patternScanner(i['what']['name'],1) == 3: #sensitive sink

			if isTainted(j['name']):
				checkAllPatterns(i['what']['name'])
			else:
				checkSanitization(i['what']['name'])

		if patternScanner(i['what']['name'],1) == 2: #sanitization
			sanitization = i['what']['name']
			paragraph = patternScanner(i['what']['name'],3) #saves the paragraph number 
			return False

		if j['kind'] == "variable" and isTainted(j['name']):
			return True


def echo(i):
	for j in i['arguments']:
		if j['kind'] == "offsetlookup":
			entrypoints[i['kind']] = j['what']['name']

	tainted[i['arguments'][0]['what']['name']] = True
	checkAllPatterns(i['kind'])

def isWhile(i):
	if i['body']: #while -> body
		for j in i['body']['children']:
			if j['kind'] == "assign": #assign
				isAssign(j)

			elif j['kind'] == "if": #if
				isIf(j, True)

			elif j['kind'] == "call": #if
				call(j)

def isTainted(var):

	if tainted.has_key(var) and tainted[var]:
		return True

	else:
		return patternScanner(var,2)

def patternScanner(value, mode):
	aux = []
	for group in patterns:

		for line in group:

			for field in line:

				if field == value:

					if mode == 1:
						return group.index(line)

					if mode == 2:
						return True

					if mode == 3:
						aux.append(patterns.index(group))
						#return patterns.index(group)
	if mode == 2:
		return False
	return aux

def recursiveVariables(var):

	for key in query:
		for value in query[key]:
			if value == var and tainted.has_key(key):
				tainted[key] = tainted[var]
				recursiveVariables(key)

def patternInicialization(filepath):

	patternFile = open(filepath, "r")

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

def conditionalVerification():
	flag = False

	for variable in conditional:

		for value in conditional[variable]:

			if value == True:
				tainted[variable] = True
				flag = True
				break

		if flag == False:
			tainted[variable] = False

def astAnalyser(astFilepath, patternsFilepath):
	global conditionalFlag
	patternInicialization(patternsFilepath)

	JSONslice = open(astFilepath, "r")
	json_data = json.load(JSONslice)

	for i in json_data['children']:
		
		if i['kind'] == "assign": #assign
			isAssign(i)
			
		if i['kind'] == "call": #call
			call(i)

		if i['kind'] == "echo": #echo
			echo(i)

		if i['kind'] == "while": #while
			isWhile(i)
			
		if i['kind'] == "if": #if
			conditionalFlag = 1
			isIf(i, False)
			conditionalVerification()
			conditionalFlag = 0

#Application Start
astAnalyser(sys.argv[1], "vulnPatterns.txt")
