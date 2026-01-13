package prospero.loader;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class GhidraProsperoElfLoader extends ElfLoader {

	public static final String PROSPERO_PROPERTY = "prospero";
	private static final String EH_FRAME_HDR = ".eh_frame_hdr";
	private static final String RODATA = ".rodata";

	private static final int EH_FRAME_PTR_OFFSET = 4;
	private static final int EH_FRAME_HDR_COUNT_OFFSET = 8;
	private static final int EH_FRAME_HDR_ENTRY_SIZE = 8;
	private static final LanguageCompilerSpecPair LANGUAGE =
		new LanguageCompilerSpecPair("x86:LE:64:default", "gcc");

	private static final Map<String, String> FRAGMENTS1 = Map.of(
		"segment_0", ".text",
		"segment_1", ".rodata",
		"segment_2", ".data.rel.ro",
		"segment_4", ".data",
		"segment_9", ".sce_rtld_data",
		"segment_10", ".sce_meta_data"
	);

	private static final Map<String, String> FRAGMENTS2 = Map.of(
		"segment_0", ".text",
		"segment_1", ".rodata",
		"segment_3", ".data.rel.ro",
		"segment_7", ".data",
		"segment_8", ".sce_rtld_data",
		"segment_10", ".sce_meta_data"
	);

	@Override
	public String getName() {
		return "Prospero ELF";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		try {
			ElfHeader header = new ElfHeader(provider, null);
			if (ProsperoElfExtension.isProsperoElf(header)) {
				return List.of((new LoadSpec(this, header.findImageBase(), LANGUAGE, true)));
			}
		} catch (ElfException e) {
		}
		return Collections.emptyList();
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return super.getTierPriority() + 1;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> options =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram, mirrorFsLayout);
		Option baseOption = options.stream()
			.filter(o -> o.getName().equals("Image Base"))
			.findFirst()
			.orElseThrow();
		long base = Long.parseUnsignedLong((String) baseOption.getValue(), 16);
		if (base == 0) {
			baseOption.setValue("1000000");
		}
		return options;
	}

	@Override
	protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms, Loader.ImporterSettings settings)
			throws CancelledException, IOException {
		
		super.postLoadProgramFixups(loadedPrograms, settings);
		for (Loaded<Program> program : loadedPrograms) {
			settings.monitor().checkCancelled();
			Program obj = program.getDomainObject(this);
			try {
				fixupProgram(obj, settings.log(), settings.monitor());
			} finally {
				obj.release(this);
			}
		}
	}

	private Group[] getFragments(Program program) {
		ProgramModule root = program.getListing().getDefaultRootModule();
		return root.getChildren();
	}

	private HashSet<String> getFragmentNames(Program program) {
		Group[] fragments = getFragments(program);
		HashSet<String> names = new HashSet<>(fragments.length);
		for (Group fragment : fragments) {
			names.add(fragment.getName());
		}
		return names;
	}

	private MemoryBlock getMemoryBlock(Program program, String name) {
		return program.getMemory().getBlock(name);
	}

	private MemoryBlock getMemoryBlock(Program program, Address addr) {
		return program.getMemory().getBlock(addr);
	}

	private void fixNames(Program program, MessageLog log, TaskMonitor monitor) throws CancelledException {
		Map<String, String> frags = getFragmentNames(program).contains("segment_9") ? FRAGMENTS1 : FRAGMENTS2;
		for (Group frag : getFragments(program)) {
			monitor.checkCancelled();
			String name = frags.get(frag.getName());
			if (name == null) {
				continue;
			}
			MemoryBlock block = getMemoryBlock(program, frag.getName());
			try {
				frag.setName(name);
				block.setName(name);
			} catch (Exception e) {
				log.appendException(e);
			}
		}
	}

	private ElfProgramHeader[] getProgramHeaders(Program program) {
		MemoryBlock block = getMemoryBlock(program, "_elfProgramHeaders");
		Data data = program.getListing().getDataAt(block.getStart());
		final int n = data.getNumComponents();
		ElfProgramHeader[] phdrs = new ElfProgramHeader[n];
		for (int i = 0; i < n; i++) {
			phdrs[i] = new ElfProgramHeader(data.getComponent(i));
		}
		return phdrs;
	}

	private Address getEhFrameAddress(Program program) {
		for (ElfProgramHeader phdr : getProgramHeaders(program)) {
			if (phdr.isEhFrame()) {
				return phdr.getAddress();
			}
		}
		return null;
	}

	private void createFragment(Program program, Address addr) throws Exception {
		MemoryBlock block = getMemoryBlock(program, addr);
		ProgramModule root = program.getListing().getDefaultRootModule();
		ProgramFragment fragment = root.createFragment(block.getName());
		Address start = block.getStart();
		fragment.move(start, start.add(block.getSize() - 1));
	}

	private MemoryBlock createBlock(Program program, Address addr, String name) throws Exception {
		MemoryBlock block = getMemoryBlock(program, addr);
		program.getMemory().split(block, addr);
		block = getMemoryBlock(program, addr);
		block.setName(name);
		createFragment(program, addr);
		return block;
	}

	private long getDword(Program program, Address addr) throws Exception {
		return program.getMemory().getInt(addr) & 0xffffffff;
	}

	private Address getEhFrameEnd(Program program) throws Exception {
		MemoryBlock block = getMemoryBlock(program, EH_FRAME_HDR);
		Address start = block.getStart();
		Address countOffset = start.add(EH_FRAME_HDR_COUNT_OFFSET);
		long count = getDword(program, countOffset);
		Address lastEntry = countOffset.add(count * EH_FRAME_HDR_ENTRY_SIZE);
		Address entryAddress = start.add(getDword(program, lastEntry));
		long endOffset = getDword(program, entryAddress);
		return entryAddress.add(endOffset + Long.BYTES);
	}

	private void fixEhFrame(Program program, MessageLog log) {
		Address addr = getEhFrameAddress(program);
		if (addr == null) {
			log.appendMsg(".eh_frame not found");
			return;
		}
		MemoryBlock block = getMemoryBlock(program, addr);
		try {
			if (block.getStart().equals(addr)) {
				block.setName(EH_FRAME_HDR);
				for (Group frag : getFragments(program)) {
					if (frag.getName().equals(RODATA)) {
						frag.setName(EH_FRAME_HDR);
					}
				}
			} else {
				createBlock(program, addr, EH_FRAME_HDR);
			}
		} catch (Exception e) {
			log.appendException(e);
		}

		try {
			Address ptr = addr.add(EH_FRAME_PTR_OFFSET);
			long pos = getDword(program, ptr);
			Address ehframeAddress = ptr.add(pos);
			MemoryBlock ehframe = createBlock(program, ehframeAddress, ".eh_frame");
			if (ehframe.getStart().equals(ehframeAddress)) {
				Address end = getEhFrameEnd(program);
				if (ehframe.getSize() > end.subtract(ehframeAddress)) {
					// rodata is at the end
					try {
						createBlock(program, end, RODATA);
					}catch (DuplicateNameException e) {
						// don't care
					}
				}
			}
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void fixupProgram(Program program, MessageLog log, TaskMonitor monitor) throws CancelledException, IOException {
		try {
			int id = program.startTransaction("program fixups");
			boolean success = false;
			try {
				program.getUsrPropertyManager().createVoidPropertyMap(PROSPERO_PROPERTY);
				fixNames(program, log, monitor);
				fixEhFrame(program, log);
				success = true;
			} finally {
				program.endTransaction(id, success);
			}
		} catch (DuplicateNameException e) {
			// impossible and if it"s somehow already set we don"t really care
		}
	}
}
