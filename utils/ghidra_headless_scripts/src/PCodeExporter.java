//Export PCode to a single machine readable file
//@author Jay Bosamiya
//@category Exporter
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedWriter;
import java.io.FileWriter;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PCodeExporter extends HeadlessScript {

	@Override
	protected void run() throws Exception {
		String output_file_name = currentProgram.getName() + ".pcode-exported";
		BufferedWriter output_file = new BufferedWriter(new FileWriter(output_file_name));

		output_file.write("PROGRAM\n");
		output_file.write("name " + currentProgram.getName() + "\n");
		output_file.write("big_endian " + currentProgram.getMemory().isBigEndian() + "\n");
		output_file.write("\n");

		output_file.write("ADDRESS_SPACES\n");
		for (AddressSpace as : currentProgram.getAddressFactory().getAddressSpaces()) {
			output_file.write("\t" + as.getSpaceID() + " " + as.getName() + " " + as.getPointerSize() + "\n");
		}
		output_file.write("\n");

		output_file.write("PCODE_LISTING\n");
		Listing listing = currentProgram.getListing();

		for (Function f : listing.getFunctions(true)) {
			output_file.write("\t" + f.getEntryPoint() + " " + f.getName() + "\n");

			PrototypeModel calling_convention = f.getCallingConvention();
			if (calling_convention == null) {
				calling_convention = currentProgram
						.getCompilerSpec()
						.getPrototypeEvaluationModel(CompilerSpec.EvaluationModelType.EVAL_CURRENT);
			}
			output_file.write("\t\tUnaffected: ");
			for (Varnode v : calling_convention.getUnaffectedList()) {
				output_file.write(v + " ");
			}
			output_file.write("\n");

			for (Address a : f.getBody().getAddresses(true)) {
				Instruction instruction = listing.getInstructionAt(a);
				if (instruction == null) {
					continue;
				}
				output_file.write("\t\t;; " + instruction.toString() + "\n");
				PcodeOp pcode[] = instruction.getPcode();
				if (pcode.length == 0) {
					output_file.write("\t\t" + a.toString() + "  ---  NOP  ---\n");
				} else {
					for (PcodeOp p : pcode) {
						String res = "\t\t" + a.toString() + " " + p;
						if (p.getOpcode() == PcodeOp.CALL || p.getOpcode() == PcodeOp.CALLIND) {
							if (instruction.hasFallthrough()) {
								res = res.replace("CALL", "CALLWITHFALLTHROUGH");
							} else {
								res = res.replace("CALL", "CALLWITHNOFALLTHROUGH");
							}
						}
						if (p.getOpcode() == PcodeOp.BRANCHIND || p.getOpcode() == PcodeOp.CALLIND) {
							res += "\tINDIRECT_TARGETS:";
							for (Address fladdr : instruction.getFlows()) {
								res += " " + fladdr.toString();
							}
						}
						if (p.getOpcode() == PcodeOp.CALLOTHER) {
							res += "\tCALLOTHER_OPCODE: ";
							res += currentProgram.getLanguage().getUserDefinedOpName((int)p.getInput(0).getOffset());
						}
						output_file.write(res + "\n");
					}
				}
			}
			output_file.write("\n");
		}
		output_file.write("\n");

		output_file.close();
		println("Done exporting to " + output_file_name);
	}
}
