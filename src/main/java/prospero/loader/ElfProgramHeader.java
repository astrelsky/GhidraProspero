package prospero.loader;

import java.util.Objects;

import ghidra.app.util.bin.format.elf.ElfProgramHeaderType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;

class ElfProgramHeader {

	private final Data data;

	ElfProgramHeader(Data data) {
		this.data = Objects.requireNonNull(data);
	}

	Program getProgram() {
		return data.getProgram();
	}

	boolean isEhFrame() {
		Scalar v = (Scalar) data.getComponent(0).getValue();
		return v.getUnsignedValue() == ElfProgramHeaderType.PT_GNU_EH_FRAME.value;
	}

	Address getAddress() {
		Scalar v = (Scalar) data.getComponent(3).getValue();
        return getProgram().getImageBase().add(v.getUnsignedValue());
	}
}
