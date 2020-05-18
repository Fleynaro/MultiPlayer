package sda;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import sda.ghidra.Server;

public class Sda {
    public static String dataTypeCategory = "SDA";

    private Program program;

    Sda(Program program)
    {
        this.program = program;

    }

    private long getBaseAddress() {
        return getProgram().getAddressMap().getImageBase().getOffset();
    }

    public long getOffsetByAddress(Address address) {
        return address.getOffset() - getBaseAddress();
    }

    public Address getAddressByOffset(long offset) {
        return getProgram().getAddressMap().getImageBase().getNewAddress(getBaseAddress() + offset);
    }

    public Program getProgram() {
        return program;
    }
}
