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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.util.Msg;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.lang.Processor;
/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class ghidra_kh2aiAnalyzer extends AbstractAnalyzer {

	public ghidra_kh2aiAnalyzer() {
		super("Function pointers resolver", "This analyzer scans KH2 AI files for "
				+ "function pointers pushed as values and resolves them.", AnalyzerType.INSTRUCTION_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyze = program.getLanguage().getProcessor().equals(
				Processor.findOrPossiblyCreateProcessor("kh2ai"));
			if (canAnalyze) {
				return true;
			}
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		//options.registerOption("Option name goes here", false, null,
		//	"Option description goes here");
	}


    // shamelessly stolen from Ghidra-Switch-Loader, creds to Adubbz
    public void createOneByteFunction(Program program, String name, Address address, boolean isEntry) {
        Function function = null;
        try {
            FunctionManager functionMgr = program.getFunctionManager();
            function = functionMgr.getFunctionAt(address);
            if (function == null) {
                function = functionMgr.createFunction(null, address, new AddressSet(address), SourceType.IMPORTED);
            }
        } catch (Exception e) {
            Msg.error(this, "Error while creating function at " + address + ": " + e.getMessage());
        }

        try {
            if (name != null) {
                createSymbol(program, address, name, false, null);
            }
            if (isEntry) {
                program.getSymbolTable().addExternalEntryPoint(address);
            }
        } catch (Exception e) {
            Msg.error(this, "Error while creating symbol " + name + " at " + address + ": " + e.getMessage());
        }
    }

    public Symbol createSymbol(Program program, Address addr, String name, boolean pinAbsolute, Namespace namespace)
            throws InvalidInputException {
        // TODO: At this point, we should be marking as data or code
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol sym = symbolTable.createLabel(addr, name, namespace, SourceType.IMPORTED);
        if (pinAbsolute && !sym.isPinned()) {
            sym.setPinned(true);
        }
        return sym;
    }


	public void getValueLabel(Program program, Instruction instruction) {
	    Address test = instruction.getAddress();
	    Scalar val = (Scalar)(instruction.getOpObjects(0)[0]);
	    if(val.getValue()!=0) {
	        long reloc=0x10+(val.getValue()<<1);
	        Address rel = program.getAddressFactory().getDefaultAddressSpace().getAddress(reloc);
	        createOneByteFunction(program, "test"+reloc, rel, true);
	    }
	}
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		// TODO: Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.
	    Listing listing = program.getListing( );
	    InstructionIterator instructionIterator = listing.getInstructions( set, true );
	    while ( instructionIterator.hasNext( ) ) {
	           Instruction instruction = instructionIterator.next( );

	            monitor.checkCanceled( );
	            monitor.incrementProgress( 1 );

	            String mnemonicString = instruction.getMnemonicString( );
	            // i have NO CLUE why but some syscalls incorrectly report a 2 item array...
	            if (mnemonicString.contains("syscall") && instruction.getInputObjects().length==3) {
	                Object[] a = instruction.getInputObjects();
	                Scalar arg1 = (Scalar)a[1];
	                Scalar arg2 = (Scalar)a[2];
	                Scalar op1= new Scalar(32, 1);
	                Scalar op2= new Scalar(32, 6);
	                
	                int args=8;
	                if (arg1.equals(op1) && arg2.equals(op2)) {
	                    Instruction copy = instruction;
	                    while(args!=0) {
	                            copy=copy.getPrevious();
	                            if (copy.getMnemonicString().contains("push.v")) {
	                                getValueLabel(program, copy);
	                                int b=0; 
	                                args--;
	                            }
	                    }
	                }
	            }
	    }

		return false;
	}
}
