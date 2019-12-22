/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra_kh2ai;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.*;


import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.data.DataUtilities.ClearDataMode;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class ghidra_kh2aiLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "KH2 AI";
	}

	public boolean checkUTF8(byte[] barr){

        CharsetDecoder decoder = Charset.forName("ASCII").newDecoder();
        ByteBuffer buf = ByteBuffer.wrap(barr);

        try {
            String head = decoder.decode(buf).toString();
            // only lowercase, underscore and numbers. hopefully this will throw less false negatives
            boolean kh = head.matches("[a-z0-9_].*");  
            if (kh) { return true; }
        }
        catch(CharacterCodingException e){
            return false;
        }

        return false;
    }	

	public Data createData(Program program, Address address, Listing listing, DataType dt) {
		try {
			Data d = listing.getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return d;
		}
		catch (CodeUnitInsertionException e) {
			Msg.warn(this, "KH2AI data markup conflict at " + address);
		}
		catch (DataTypeConflictException e) {
			Msg.error(this, "KH2AI data type markup conflict:" + e.getMessage());
		}
		return null;
	}
	
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (checkUTF8(provider.readBytes(0,0x10)) & !checkUTF8(provider.readBytes(0x10,0x20))) {
			loadSpecs.add(new LoadSpec(this, 0,
					new LanguageCompilerSpecPair("kh2_ai:le:32:default", "default"), true));
		}
		return loadSpecs;
	}

	public boolean checkZero(byte[] arr) {
		for (byte b : arr) {
			if (b != 0) {
				return false;
			}
		}
		return true;
	}

	public static final long arrToLong(byte[] b) 
	{
	    long l = 0;
	    l |= b[3] & 0xFF;
	    l <<= 8;
	    l |= b[2] & 0xFF;
	    l <<= 8;
	    l |= b[1] & 0xFF;
	    l <<= 8;
	    l |= b[0] & 0xFF;
	    return l;
	}

	// shamelessly stolen from Ghidra-Switch-Loader, creds to Adubbz
    public void createOneByteFunction(Program program, String name, Address address, boolean isEntry) 
    {
        Function function = null;
        try 
        {
            FunctionManager functionMgr = program.getFunctionManager();
            function = functionMgr.getFunctionAt(address);
            if (function == null) {
                function = functionMgr.createFunction(null, address, new AddressSet(address), SourceType.IMPORTED);
            }
        }
        catch (Exception e) 
        {
            Msg.error(this, "Error while creating function at " + address + ": " + e.getMessage());
        }

        try 
        {
            if (name != null) 
            {
                createSymbol(program, address, name, false, null);
            }
            if (isEntry) {
                program.getSymbolTable().addExternalEntryPoint(address);
            }
        }
        catch (Exception e) {
            Msg.error(this, "Error while creating symbol " + name + " at " + address + ": " + e.getMessage());
        }
    }
    
    public Symbol createSymbol(Program program, Address addr, String name, boolean pinAbsolute, Namespace namespace) throws InvalidInputException
    {
        // TODO: At this point, we should be marking as data or code
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol sym = symbolTable.createLabel(addr, name, namespace, SourceType.IMPORTED);
        if (pinAbsolute && !sym.isPinned()) {
            sym.setPinned(true);
        }
        return sym;
    }
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		// We create the header structure and add the static elements
		Structure struct = new StructureDataType("header", 0);
		struct.add(ghidra.app.util.bin.StructConverter.STRING, 0x10, "filename", null);
		struct.add(ghidra.app.util.bin.StructConverter.DWORD, 4, "unk1", null);
		struct.add(ghidra.app.util.bin.StructConverter.DWORD, 4, "unk2", null);
		struct.add(ghidra.app.util.bin.StructConverter.DWORD, 4, "unk3", null);
		
		int off = 0;
		ArrayList<Long> entrypoints = new ArrayList<Long>();
		while (1==1) {
			// gathers entrypoints/triggers into an arraylist and define the dynamic part of the header structure
			byte[] first = provider.readBytes(0x1c+(off*8), 0x4);
			byte[] second = provider.readBytes(0x1c+4+(off*8), 0x4);
			if(checkZero(first) && checkZero(second)){
				struct.add(ghidra.app.util.bin.StructConverter.DWORD, 4, "end_trigger", null);
				struct.add(ghidra.app.util.bin.StructConverter.DWORD, 4, "end_entry", null);
				break;
			}
			long fa = arrToLong(first);
			long sa = arrToLong(second);
			entrypoints.add(fa);
			entrypoints.add(sa);
			log.appendMsg("kh2ai: " + fa + " " + sa);
			struct.add(ghidra.app.util.bin.StructConverter.DWORD, 4, "trigger"+(off+1), null);
			struct.add(ghidra.app.util.bin.StructConverter.DWORD, 4, "entry"+(off+1), null);
			off++;
		}
		log.appendMsg("kh2ai: " + entrypoints);

		// we actually send the bytes over to the program and send off the header structure
		MemoryBlockUtils mbu = new MemoryBlockUtils();
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		BinaryReader reader = new BinaryReader( provider, true );
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, TaskMonitor.DUMMY);
		try {
			MemoryBlockUtils.createInitializedBlock(program, false, "ram", start, fileBytes, 0, provider.length(), "", "KH2AI Header", true, true, true, log);
		} catch (AddressOverflowException e) {
			e.printStackTrace();
		}
		createData(program, start, program.getListing(), struct);

		// we create one byte functions so that the analyzer knows that there's something there, labelling 
		// entrypoints in the format entry<trigger>
		for (int i=0; i<entrypoints.size(); i+=2) {
			long addr=0x10+(entrypoints.get(i+1)<<1);
			Address entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
			createOneByteFunction(program, "entry"+entrypoints.get(i), entry, true); 
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		//list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
