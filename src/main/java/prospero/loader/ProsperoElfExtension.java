package prospero.loader;

import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfProgramHeaderType;
import ghidra.app.util.bin.format.elf.ElfDynamicType.ElfDynamicValueType;
import ghidra.app.util.bin.format.elf.extend.ElfExtension;

public class ProsperoElfExtension extends ElfExtension {

	private static final byte ABI_VERSION = 2;
	private static final short MACHINE_TYPE = 0x3e;
	private static final short PROGRAM_TYPE = (short) 0xFE10;
    public static final short LIB_TYPE = (short) 0xFE18;

	public static final ElfProgramHeaderType PT_SCE_PROCPARAM = new ElfProgramHeaderType(
		0x61000001, "SCE_PROCPARAM", "");
	public static final ElfProgramHeaderType PT_SCE_MODULEPARAM = new ElfProgramHeaderType(
		0x61000002, "SCE_MODULEPARAM", "");
	public static final ElfProgramHeaderType PT_SCE_COMMENT = new ElfProgramHeaderType(
		0x6FFFFF00, "SCE_COMMENT", "");
	public static final ElfProgramHeaderType PT_SCE_LIBVERSION = new ElfProgramHeaderType(
		0x6FFFFF01, "SCE_LIBVERSION", "");

	// dynamic types
	public static final ElfDynamicType DT_SCE_IDTABENTSZ = new ElfDynamicType(
		0x61000005, "SCE_IDTABENTSZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_FINGERPRINT = new ElfDynamicType(
		0x61000007, "SCE_FINGERPRINT", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_ORIGINAL_FILENAME = new ElfDynamicType(
		0x61000009, "SCE_ORIGINAL_FILENAME", "", ElfDynamicValueType.STRING);
	public static final ElfDynamicType DT_SCE_MODULE_INFO = new ElfDynamicType(
		0x6100000D, "SCE_MODULE_INFO", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_NEEDED_MODULE = new ElfDynamicType(
		0x6100000F, "SCE_NEEDED_MODULE", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_MODULE_ATTR = new ElfDynamicType(
		0x61000011, "SCE_MODULE_ATTR", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_EXPORT_LIB = new ElfDynamicType(
		0x61000013, "SCE_EXPORT_LIB", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_IMPORT_LIB = new ElfDynamicType(
		0x61000015, "SCE_IMPORT_LIB", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_EXPORT_LIB_ATTR = new ElfDynamicType(
		0x61000017, "SCE_EXPORT_LIB_ATTR", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_IMPORT_LIB_ATTR = new ElfDynamicType(
		0x61000019, "SCE_IMPORT_LIB_ATTR", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_STUB_MODULE_NAME = new ElfDynamicType(
		0x6100001D, "SCE_STUB_MODULE_NAME", "", ElfDynamicValueType.STRING);
	public static final ElfDynamicType DT_SCE_STUB_MODULE_VERSION = new ElfDynamicType(
		0x6100001F, "SCE_STUB_MODULE_VERSION", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_STUB_LIBRARY_NAME = new ElfDynamicType(
		0x61000021, "SCE_STUB_LIBRARY_NAME", "", ElfDynamicValueType.STRING);
	public static final ElfDynamicType DT_SCE_STUB_LIBRARY_VERSION = new ElfDynamicType(
		0x61000023, "SCE_STUB_LIBRARY_VERSION", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_HASH = new ElfDynamicType(
		0x61000025, "SCE_HASH", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_PLTGOT = new ElfDynamicType(
		0x61000027, "SCE_PLTGOT", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_JMPREL = new ElfDynamicType(
		0x61000029, "SCE_JMPREL", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_PLTREL = new ElfDynamicType(
		0x6100002B, "SCE_PLTREL", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_PLTRELSZ = new ElfDynamicType(
		0x6100002D, "SCE_PLTRELSZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_RELA = new ElfDynamicType(
		0x6100002F, "SCE_RELA", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_RELASZ = new ElfDynamicType(
		0x61000031, "SCE_RELASZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_RELAENT = new ElfDynamicType(
		0x61000033, "SCE_RELAENT", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_STRTAB = new ElfDynamicType(
		0x61000035, "SCE_STRTAB", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_STRSZ = new ElfDynamicType(
		0x61000037, "SCE_STRSZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_SYMTAB = new ElfDynamicType(
		0x61000039, "SCE_SYMTAB", "", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_SCE_SYMENT = new ElfDynamicType(
		0x6100003B, "SCE_SYMENT", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_HASHSZ = new ElfDynamicType(
		0x6100003D, "SCE_HASHSZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_SYMTABSZ = new ElfDynamicType(
		0x6100003F, "SCE_SYMTABSZ", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_HIOS = new ElfDynamicType(
		0x6FFFF000, "SCE_HIOS", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_IMPORT_MODULE = new ElfDynamicType(
		0x61000045, "SCE_IMPORT_MODULE", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_SCE_IMPORT_LIBRARY = new ElfDynamicType(
		0x61000049, "SCE_IMPORT_LIBRARY", "", ElfDynamicValueType.VALUE);

	static boolean isProsperoElf(ElfHeader elf) {
		short type = elf.e_type();
		short machine = elf.e_machine();
		byte abi = elf.e_ident_abiversion();

		return machine == MACHINE_TYPE && (type == PROGRAM_TYPE || type == LIB_TYPE) && abi >= ABI_VERSION;
	}

	@Override
	public boolean canHandle(ElfHeader elf) {
		return isProsperoElf(elf);
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		return isProsperoElf(elfLoadHelper.getElfHeader());
	}

	@Override
	public String getDataTypeSuffix() {
		return null;
	}

}
