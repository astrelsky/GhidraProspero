package prospero.analysis;

import java.util.Collections;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import prospero.loader.GhidraProsperoElfLoader;
import prospero.db.ImportManager;
import prospero.nid.NidDatabaseFactory;

public class NIDAnalyzer extends AbstractAnalyzer {

	public NIDAnalyzer() {
		super(NIDAnalyzer.class.getSimpleName(), "NID Resolver", AnalyzerType.BYTE_ANALYZER);
		// run first for non-returning functions
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.before());
		setSupportsOneTimeAnalysis();
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getUsrPropertyManager().getVoidPropertyMap(GhidraProsperoElfLoader.PROSPERO_PROPERTY) != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		try {
			NIDResolver resolver = new NIDResolver(program, log);
			SymbolTable table = program.getSymbolTable();
			monitor.initialize(table.getNumSymbols());
			monitor.setMessage("Resolving NIDs");
			for (Symbol s : table.getAllSymbols(false)) {
				// remaining symbols are data but the library namespace
				// cannot be added for some reason
				monitor.checkCancelled();
				if (s.isPrimary() && s.getName().contains("#")) {
					resolver.resolve(s);
				}
				monitor.incrementProgress(1);
			}
			return true;
		} catch (CancelledException e) {
			throw e;
		} catch (Exception e) {
			log.appendException(e);
		}
		return false;
	}

	private static class NIDResolver {

		private final Map<String, String> db;
		private final MessageLog log;
		private final ExternalManager man;
		private final SymbolTable table;
		private final ImportManager importMan;

		NIDResolver(Program program, MessageLog log) {
			Map<String, String> db = Collections.emptyMap();
			ImportManager importMan = null;
			try {
				db = NidDatabaseFactory.getNidDatabase();
				importMan = new ImportManager(program);
				importMan.fillLibraries();
			} catch (Exception e) {
				log.appendException(e);
			}
			this.db = db;
			this.log = log;
			this.man = program.getExternalManager();
			this.table = program.getSymbolTable();
			this.importMan = importMan;
		}

		void resolve(Symbol s) throws Exception {
			Namespace ns = s.getParentNamespace();
			String name = s.getName();
			if (name.length() < 11 || name.charAt(11) != '#') {
				return;
			}
			int id = name.charAt(12);
			if (name.length() <= 15) {
				if (name.charAt(13) == '#') {
					if (importMan.containsLibrary(id)) {
						ns = getExternalLibrary(id);
					}
				} else if (name.charAt(14) == '#') {
					id = name.charAt(13);
					if (importMan.containsLibrary(id)) {
						ns = getExternalLibrary(id);
					}
				} else {
					return;
				}
			}
			name = name.substring(0, 11);
			if (db.containsKey(name)) {
				name = db.get(name);
			}
			if (ns == null) {
				ns = s.getProgram().getGlobalNamespace();
			}
			try {
				s.setNameAndNamespace(name, ns, SourceType.IMPORTED);
				if (name.equals("__stack_chk_fail")) {
					if (s.getSymbolType() == SymbolType.FUNCTION) {
						Function fun = (Function) s.getObject();
						fun.setNoReturn(true);
					}
				}
			} catch (InvalidInputException e) {
				// occurs for data
				ExternalLocation loc = man.getExternalLocation(s);
				if (loc == null) {
					man.addExtLocation(ns, name, null, SourceType.IMPORTED);
				}
				s = table.createLabel(s.getAddress(), name, SourceType.IMPORTED);
				s.setPrimary();
			} catch (Exception e) {
				log.appendException(e);
			}
		}

		private Library getExternalLibrary(int index) throws Exception {
			if (importMan.isCurrentLibrary(index)) {
				return null;
			}
			String name = importMan.getLibraryName(index);
			Library lib = man.getExternalLibrary(name);
			if (lib == null) {
				lib = man.addExternalLibraryName(name, SourceType.IMPORTED);
			}
			return lib;
		}
	}
}
