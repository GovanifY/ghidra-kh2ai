# This script imports a Kh2Ai file into Ghidra
#@author Gauvain "GovanifY" Roussel-Tarbouriech 
#@category Import
#@keybinding 
#@menupath 
#@toolbar 

import struct
import sys
import os.path

# import the file into ghidra db
file = askFile("Select AI object (*.ai) to import", "Import")
lang = getDefaultLanguage(ghidra.program.model.lang.Processor.findOrPossiblyCreateProcessor("kh2ai"))
comp = lang.getDefaultCompilerSpec()
program = importFileAsBinary(file, lang, comp)
ai = open(file.toString(), "rb")
flat = ghidra.program.flatapi.FlatProgramAPI(program)
txn = program.startTransaction("Import program")
mem = program.getMemory()
start = mem.getMinAddress()



# read header
entry=[]
ai_name = ai.read(0x10).decode('utf-8') 
unk1, unk2, unk3 = struct.unpack("<3L", ai.read(0xc))
print("ai: %s, header: %s %s %s" % (ai_name, hex(unk1), hex(unk2), hex(unk3)))

# document header (very important!!11!)
flat.createLabel(start, "header", True)
flat.createAsciiString(start, 0x10)
for i in range(0, 3):
	flat.createDWord(start.add(0x10+i*4))

# read out all entrypoints and callbacks
while True:
    callback, offset = struct.unpack("<2L", ai.read(0x8))
    if(callback == 0 and offset == 0):
        flat.createLabel(start.add(0x1c+len(entry)*8), "header_end", True)
        flat.createDWord(start.add(0x1c+len(entry)*8))
        flat.createDWord(start.add(0x1c+4+len(entry)*8))
        break
    print("entry%s: %s" % (callback, hex(0x10+offset*2)))
    flat.createLabel(start.add(0x1c+len(entry)*8), "entry"+str(callback), True)
    flat.createDWord(start.add(0x1c+len(entry)*8))
    flat.createDWord(start.add(0x1c+4+len(entry)*8))
    entry.append([callback, 0x10+offset*2])
print(entry)
ai.close()


for i in entry:
    label="entry"+str(i[0])
    flat = ghidra.program.flatapi.FlatProgramAPI(program)
    flat.createLabel(start.add(i[1]), label, True)
    flat.addEntryPoint(start.add(i[1]))
    flat.disassemble(start.add(i[1]))

# Open for user to see and to start analyzing
program.endTransaction(txn, True)
openProgram(program)

