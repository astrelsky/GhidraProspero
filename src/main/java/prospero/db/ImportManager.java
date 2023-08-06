package prospero.db;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.app.util.bin.format.elf.ElfProgramHeaderType;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;

import db.*;

public final class ImportManager {

	private static final int ELF_PHDR_TYPE_ORDINAL = 0;
	private static final int ELF_PHDR_VADDR_ORDINAL = 3;

	private static final int ELF_DYN_TYPE_ORDINAL = 0;
	private static final int ELF_DYN_VALUE_ORDINAL = 1;

	private static final String TABLE_NAME = "Prospero Import Libraries";
	private static final Schema SCHEMA =
		new Schema(1, "ID", new Class<?>[] { StringField.class }, new String[] { "Name" });

	private final DBHandle db;
	private final Table table;
	private final Program program;

	public ImportManager(Program program) throws IOException {
		this.program = program;
		this.db = ((ProgramDB) program).getDBHandle();
		Table table = db.getTable(TABLE_NAME);
		if (table == null) {
			table = db.createTable(TABLE_NAME, SCHEMA);
		}
		this.table = table;
	}

	public boolean isCurrentLibrary(int index) throws IOException {
		String name = getLibraryName(index);
		return name.isEmpty();
	}

	private Data getDynamic(Program program) {
		MemoryBlock block = program.getMemory().getBlock("_elfProgramHeaders");
		Data data = program.getListing().getDataAt(block.getStart());
		final int n = data.getNumComponents();
		for (int i = 0; i < n; i++) {
			Data comp = data.getComponent(i);
			Scalar s = (Scalar) comp.getComponent(ELF_PHDR_TYPE_ORDINAL).getValue();
			if (s.getUnsignedValue() == ElfProgramHeaderType.PT_DYNAMIC.value) {
				s = (Scalar) comp.getComponent(ELF_PHDR_VADDR_ORDINAL).getValue();
				Address addr = program.getImageBase().add(s.getUnsignedValue());
				return program.getListing().getDataAt(addr);
			}
		}
		return null;
	}

	public void fillLibraries() throws IOException {
		Data data = getDynamic(program);
		MemoryBlock block = program.getMemory().getBlock(data.getAddress());
		MemoryByteProvider provider = new MemoryByteProvider(program.getMemory(), block.getStart());
		BinaryReader reader = new BinaryReader(provider, true);
		final int n = data.getNumComponents();
		int currentId = 'A';
		for (int i = 0; i < n; i++) {
			Data comp = data.getComponent(i);
			Scalar s = (Scalar) comp.getComponent(ELF_DYN_TYPE_ORDINAL).getValue();
			long value = s.getUnsignedValue();
			if (value == ElfDynamicType.DT_NEEDED.value) {
				s = (Scalar) comp.getComponent(ELF_DYN_VALUE_ORDINAL).getValue();
				String lib = reader.readAsciiString(s.getUnsignedValue());
				addLibrary(lib, currentId++);
			} else if (value == ElfDynamicType.DT_SONAME.value) {
				addLibrary("", currentId++);
			}
		}
	}

	public void addLibrary(String name, long id) throws IOException {
		DBRecord record = table.getRecord(id);
		if (record != null) {
			return;
		}
		record = SCHEMA.createRecord(id);
		record.setString(0, name);
		table.putRecord(record);
	}

	public boolean containsLibrary(long id) throws IOException {
		return table.hasRecord(id);
	}

	public String getLibraryName(long id) throws IOException {
		DBRecord record = table.getRecord(id);
		if (record == null) {
			return null;
		}
		return record.getString(0);
	}
}
