package sda.managers;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import sda.Sda;

public abstract class AbstractManager {

    private Sda sda;

    public AbstractManager(Sda sda)
    {
        this.sda = sda;
    }

    private long getBase() {
        return getProgram().getAddressMap().getImageBase().getOffset();
    }

    public long getOffset(Address address) {
        return address.getOffset() - getBase();
    }

    public Address getAddress(long offset) {
        return getProgram().getAddressMap().getImageBase().getNewAddress(getBase() + offset);
    }

    public Address getAddress(int offset) {
        return getAddress((long)offset);
    }

    public Program getProgram() {
        return getSDA().getProgram();
    }

    public Sda getSDA() {
        return sda;
    }
}
