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
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
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
			String symbol = s.getName();
			if (symbol.indexOf('#') == -1) {
				return;
			}
			NidInfo info = new NidInfo(s.getName());
			String name = db.get(info.nid);
			try {
				if (name == null) {
					Namespace parent = s.getParentNamespace();
					if (parent instanceof Library && !parent.getName().equals("<EXTERNAL>")) {
						// already processed
						return;
					}
					ns = getExternalLibrary(info.getId());
					if (ns != null) {
						s.setNamespace(ns);
					}
					return;
				}
				ns = getExternalLibrary(info.getId());
				if (ns == null) {
					Msg.warn(this, "Failed to get library for " + symbol);
					ns = s.getProgram().getGlobalNamespace();
				}
				s.setNameAndNamespace(name, ns, SourceType.IMPORTED);
				if (name.equals("__stack_chk_fail")) {
					if (s.getSymbolType() == SymbolType.FUNCTION) {
						Function fun = (Function) s.getObject();
						fun.setNoReturn(true);
					}
				}
			} catch (InvalidInputException e) {
				// occurs for data
				if (name == null) {
					name = symbol;
				}
				ExternalLocation loc = man.getExternalLocation(s);
				if (loc == null) {
					man.addExtLocation(ns, name, null, SourceType.IMPORTED);
				}
				if (s.getAddress().isExternalAddress()) {
					s.setName(name, SourceType.IMPORTED);
				} else {
					s = table.createLabel(s.getAddress(), name, SourceType.IMPORTED);
					s.setPrimary();
				}
			} catch (Exception e) {
				log.appendException(e);
			}
		}


		private Library getExternalLibrary(long index) throws Exception {
			String name = importMan.getLibraryName(index);
			if (name == null) {
				return null;
			}
			Library lib = man.getExternalLibrary(name);
			if (lib == null) {
				lib = man.addExternalLibraryName(name, SourceType.IMPORTED);
			}
			return lib;
		}
	}

	private static class NidInfo {
		final String nid;
		final String lid;
		//final String mid;

		NidInfo(String symbol) {
			String[] parts = symbol.split("#");
			if (parts.length > 0) {
				nid = parts[0];
			} else {
				nid = "";
			}
			if (parts.length > 1) {
				lid = parts[1];
			} else {
				lid = "";
			}
			/*if (parts.length > 2) {
				mid = parts[2];
			} else {
				mid = "";
			}*/
		}

		private static long charToId(int c) {
			if (c >= 'A' && c <= 'Z') {
				return c - 'A';
			}
			if (c >= 'a' && c <= 'z') {
				return c - 'a' + 26;
			}
			if (c >= '0' && c <= '9') {
				return c - '0' + 52;
			}
			if (c == '+') {
				return 62;
			}
			if (c == '-') {
				return 63;
			}
			throw new IllegalArgumentException("Invalid nid character " + c);
		}

		long getId() {
			if (lid.length() == 1) {
				return charToId(lid.charAt(0));
			}
			if (lid.length() == 2) {
				long value = 0;
				for (int c = lid.charAt(0); c > 'A'; c--) {
					value += 64;
				}
				return value + charToId(lid.charAt(1));
			}
			throw new AssertException("NID's LIBID is more than 2 characters");
		}
	}
}
