package sda;

import ghidra.program.model.listing.Program;
import sda.ghidra.Server;
import sda.managers.DataTypeManager;
import sda.managers.FunctionManager;

public class Sda {
    private Program program;
    private DataTypeManager dataTypeManager;
    private FunctionManager functionManager;

    Sda(Program program)
    {
        this.program = program;
        this.dataTypeManager = new DataTypeManager(this);
        this.functionManager = new FunctionManager(this);
    }

    public DataTypeManager getDataTypeManager() {
        return dataTypeManager;
    }
    public FunctionManager getFunctionManager() {
        return functionManager;
    }

    public Program getProgram() {
        return program;
    }
}
