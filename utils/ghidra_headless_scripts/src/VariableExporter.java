//Export variable information to a single machine readable file
//@author Jay Bosamiya
//@category Exporter
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.Map;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.Varnode;

public class VariableExporter extends HeadlessScript {
	private void dwarf_only_unless_default_allowed() throws Exception {
		// Unless explicitly `allow_default_analysis` is requested,
		// make sure we only run DWARF analysis, and otherwise run no other auto-analysis

		Boolean allow_default_analysis = false;
		for (String arg : getScriptArgs()) {
			if (arg.contentEquals("allow_default_analysis")) {
				allow_default_analysis = true;
			} else {
				throw new Exception("Unexpected script argument: " + arg);
			}
		}
		if (allow_default_analysis) {
			return;
		}

		if (isHeadlessAnalysisEnabled()) {
			throw new Exception("Expected `-noanalysis`");
		}
		resetAllAnalysisOptions(currentProgram);
		for (Map.Entry<String, String> v: this.getCurrentAnalysisOptionsAndValues(currentProgram).entrySet()) {
			if (!v.getKey().contains(".")) {
				if (v.getKey().contentEquals("DWARF")) {
					println("Keeping " + v.getKey() + " enabled");
				} else {
					this.setAnalysisOption(currentProgram, v.getKey(), "false");
				}
			}
		}
		this.enableHeadlessAnalysis(true);
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
		mgr.startAnalysis(monitor);
		this.analyzeAll(currentProgram);
	}

	@Override
	protected void run() throws Exception {
		this.dwarf_only_unless_default_allowed();
		String output_file_name = currentProgram.getName() + ".var-exported";
		@SuppressWarnings("resource")
		BufferedWriter output_file = new BufferedWriter(new FileWriter(output_file_name));

		output_file.write("PROGRAM\n");
		output_file.write("name " + currentProgram.getName() + "\n");
		Register sp = currentProgram.getCompilerSpec().getStackPointer();
		output_file.write("stack_pointer\t" + sp + "\t" +
			new Varnode(sp.getAddress(), sp.getMinimumByteSize()) + "\n");
		output_file.write("\n");

		output_file.write("VARIABLES\n");
		Listing listing = currentProgram.getListing();
		for (Function f : listing.getFunctions(true)) {
			if (f.isThunk()) {
				continue;
			}
			for (Variable var : f.getAllVariables()) {
				String varname = var.getName() + "@" + f.getName() + "@" + f.getEntryPoint();
				if (varname.contains("\t") || var.getName().contains("@") || f.getName().contains("@")) {
					throw new Exception("ERROR: Contains invalid char in variable name: " + varname);
				}
				output_file.write("\t" + varname + "\n");
				for (Varnode vn : var.getVariableStorage().getVarnodes()) {
					output_file.write("\t\t" + vn + "\n");
				}
			}
		}
		output_file.write("\n");

		output_file.close();
		println("Done exporting to " + output_file_name);
	}
}
