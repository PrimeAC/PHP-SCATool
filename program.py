import json
import sys


patterns = []

tainted = {}

entrypoints = {}
sanitization = {} 
sensitive = {}
query = {}

paragraph = -1
conditionalFlag = 0

def checkVulnerability(sink):

	for entry in entrypoints:
		if checkPattern(entrypoints[entry], sink, paragraph):
			print "Vulnerable"
			sys.exit(0)
		else:
			#print "ESTE -------"
			print "Not vulnerable"
			sys.exit(0)

def checkPattern(sink):
	
	for entry in entrypoints:
		if paragraph != -1: #means that exists sanitization previously

			if entry in patterns[paragraph][1]:
				if sink in patterns[paragraph][3]:
					checkVulnerability(False, [list(sanitization)[0]])  #false due to valid danitization for entry and sink
				else:
					checkVulnerability(False, ["sink used is not valid"])
			elif sink in patterns[paragraph][3]:
				checkVulnerability(False, ["entry point used is not valid"]) 
			else:  #vulnerable
				checkVulnerability(True, [patterns[paragraph][0][0], patterns[paragraph][0]])

		else: #there was no sanitization previously

			for pattern in patterns:

				if entry in pattern[1] and sink in pattern[3]:
					checkVulnerability(True, [patterns[paragraph][0][0], patterns[paragraph][0]])

			else:
				checkVulnerability(False, ["entry point does not match with sensitive sink"])


def isAssign(i):
	
	#print str(conditionalFlag) + " cond flag"
	if i['right']['kind'] == "offsetlookup": #assign -> offsetlookup

			entrypoints[i['left']['name']] = i['right']['what']['name']
			tainted[i['left']['name']] = isTainted(i['right']['what']['name'])

	if i['right']['kind'] == "encapsed": #assign -> encapsed
		query[i['left']['name']] = []
		
		for j in i['right']['value']:
			
			if j['kind'] == "variable":
				query[i['left']['name']].append(j['name'])
				
				if isTainted(j['name']) and conditionalFlag == 0 and tainted.has_key(i['left']['name']) == False: #e preciso estas condicoes todas?
					print "ENTREI NO IF 1 " + str(i['left']['name']) + " - " + str(j['name'])
					tainted[i['left']['name']] = True
				elif conditionalFlag == 0 and tainted.has_key(i['left']['name']) == False:
					print "ENTREI NO ELIF 1"
					tainted[i['left']['name']] = False

	if i['right']['kind'] == "bin": #assign -> bin
		query[i['left']['name']] = []
		
		if i['right']['left']['kind'] == "variable":
			query[i['left']['name']].append(i['right']['left']['name'])

		if i['right']['right']['kind'] == "variable":
			query[i['left']['name']].append(i['right']['right']['name'])

		if isTainted(i['right']['right']['name']):
			tainted[i['left']['name']] = tainted[i['right']['right']['name']]
		elif isTainted(i['right']['left']['name']):
			tainted[i['left']['name']] = tainted[i['right']['left']['name']]


	if i['right']['kind'] == "call": #assign -> call
		sensitive[i['right']['what']['name']] = []
		sanitization[i['right']['what']['name']] = []
		#print str(sanitization) + "RRRRRRRRRRRRRRRRRRRRRR" 

		#new implementation
		tainted[i['left']['name']] = call(i['right'])


	if i['right']['kind'] == "variable": #assign -> variable
		query[i['left']['name']] = [i['right']['name']]
		if isTainted(i['right']['name']) and conditionalFlag == 0 and tainted.has_key(i['left']['name']) == False:
			print "ENTREI NO IF"
			tainted[i['left']['name']] = True
			recursiveVariables(i['left']['name'])
		elif conditionalFlag == 0 and tainted.has_key(i['left']['name']) == False:
			print "ENTREI NO ELIF"
			tainted[i['left']['name']] = False


def isIf(i, recursion):
	#print "ISif " +str(conditionalFlag)
	for line in i['body']['children']:
		if line['kind'] == "assign":
			isAssign(line)

		if line['kind'] == 'call':
			call(line)

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
	#print str(paragraph) + " PARAADSFSAF"
	sensitive[i['what']['name']] = []

	for j in i['arguments']:
		
		if patternScanner(i['what']['name'],1) == 3: #sensitive sink
			if len(sanitization):
				#print "sanitizacao"		
				del sanitization[list(sanitization)[0]] #delete all the non sanitization methods
			if isTainted(j['name']):
				checkVulnerability(i['what']['name'])
			else:							#se o que entrar no sink nao estiver tainted nao quer dizer que seja nao vulneravel
											#pode ter sido feita uma ma sanitizacao e continuar a ser vulneravel
											#so se for tainted e que se pode assumir que e vulneravel e so se tem de comparar se o entry bate certo com o sink
				#print "AQUELE -------"
				checkVulnerability(i['what']['name'])	

		if patternScanner(i['what']['name'],1) == 2: #sanitization
			sanitization[i['what']['name']].append(j['name'])
			paragraph = patternScanner(i['what']['name'],3) #saves the paragraph number 
			return False

		if j['kind'] == "variable" and isTainted(j['name']):
			sensitive[i['what']['name']].append(j['name'])
			return True


def echo(i):
	for j in i['arguments']:
		if j['kind'] == "offsetlookup":
			entrypoints[i['kind']] = j['what']['name']

	sensitive[i['kind']] = [i['arguments'][0]['what']['name']]
	tainted[i['arguments'][0]['what']['name']] = True
	checkVulnerability(i['kind'])

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

	for group in patterns:

		for line in group:

			for field in line:

				if field == value:

					if mode == 1:
						return group.index(line)

					if mode == 2:
						return True

					if mode == 3:
						return patterns.index(group)
	if mode == 2:
		return False

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
			#print str(conditionalFlag) + "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" 
			isIf(i, False)
			conditionalFlag = 0


	#print(entrypoints)
	#print(sensitive)
	#print(query)
	#print(tainted)

astAnalyser(sys.argv[1], "vulnPatterns.txt")


''' a conditionalFlag esta sempre a zero porque nao e global logo a igualacao a 1 e so temporaria e a partir do momento em que se chama o isif ela volta a ser 0
o mesmo problema para o paragraph pois ta a ser mal declarada como global
'''