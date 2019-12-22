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
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
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
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.program.model.lang.Processor;
import ghidra.app.cmd.comments.AppendCommentCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.function.FunctionAnalyzer;
/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class ghidra_kh2aiAnalyzer extends AbstractAnalyzer {

    public boolean new_pass=false;

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
    public boolean createOneByteFunction(Program program, String name, Address address, boolean isEntry) {
        Function function = null;
        boolean newf = false;
        try {
            FunctionManager functionMgr = program.getFunctionManager();
            function = functionMgr.getFunctionAt(address);
            if (function == null) {
                function = functionMgr.createFunction(null, address, new AddressSet(address), SourceType.IMPORTED);
            } else { newf = true; }
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
        return newf;
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

    
	public void getValueLabel(Program program, Instruction instruction, Listing listing) {
	    Address test = instruction.getAddress();
	    Scalar val = (Scalar)(instruction.getOpObjects(0)[0]);
	    if(val.getValue()!=0) {
	        long reloc=0x10+(val.getValue()<<1);
	        Address rel = program.getAddressFactory().getDefaultAddressSpace().getAddress(reloc);
	        if (createOneByteFunction(program, null, rel, true) == false) {new_pass=true;}
	        listing.setComment(test, CodeUnit.EOL_COMMENT, "pointer to: "+Long.toHexString(reloc));
	        Disassembler disassembler = Disassembler.getDisassembler(program, TaskMonitorAdapter.DUMMY_MONITOR, null);
	        disassembler.disassemble(rel, null);
	    }
	}
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
	    // we don't want to enter an infinite loop of new passes
	    new_pass=false;

	    Listing listing = program.getListing( );
	    InstructionIterator instructionIterator = listing.getInstructions( set, true );
	    while ( instructionIterator.hasNext( ) ) {
	           Instruction instruction = instructionIterator.next( );

	            monitor.checkCanceled( );
	            monitor.incrementProgress( 1 );

	            String mnemonicString = instruction.getMnemonicString( );
	            // i have NO CLUE why but some syscalls incorrectly report a 2 item array...
	            if (mnemonicString.contains("syscall")) {
	                Scalar arg1 = (Scalar)instruction.getOpObjects(0)[0];
	                Scalar arg2 = (Scalar)instruction.getOpObjects(1)[0];
	                
	                // yeah ok this might be a _little_ hardcoded right now but hey, it works
	                // TODO: store syscalls/args positions and pointers in a resource file and do that automagically
	                if (arg1.getValue()==1 && arg2.getValue()==6) {
	                    Instruction copy = instruction;
	                    int args=8+1;
	                    while(args!=0) {
	                            copy=copy.getPrevious();
	                            if (copy.getMnemonicString().contains("push.v")) {
	                                getValueLabel(program, copy, program.getListing());
	                                args--;
	                            }
	                    }
	                }
	            }
	    }
	    // kind of a bottleneck but note like kh2 ai is going to be more than 100kb ever
	    if(new_pass ) {
	        // we added a bunch of functions, might be a good idea to do another pass
	        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
	        mgr.reAnalyzeAll(null);
	    }

		return true;
	}
}
