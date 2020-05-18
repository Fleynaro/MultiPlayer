package sda.sync;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import sda.Sda;
import sda.ghidra.datatype.SDataTypeClass;
import sda.ghidra.packet.SDataFullSyncPacket;
import sda.sync.mappers.DataTypeMapper;
import sda.sync.mappers.FunctionMapper;

import java.util.ArrayList;
import java.util.Iterator;

public class Sync {

    private Sda sda;
    private DataTypeMapper dataTypeMapper;
    private FunctionMapper functionMapper;

    public Sync(Sda sda) {
        this.sda = sda;
        dataTypeMapper = new DataTypeMapper(sda, sda.getProgram().getDataTypeManager());
        functionMapper = new FunctionMapper(sda, sda.getProgram().getFunctionManager(), dataTypeMapper);
    }

    public void loadDataFullSyncPacket(SDataFullSyncPacket dataPacket) {
        dataTypeMapper.load(dataPacket);
        functionMapper.load(dataPacket);
    }

    public SDataFullSyncPacket buildDataFullSyncPacket() {
        SyncContext ctx = new SyncContext();
        ctx.dataPacket = new SDataFullSyncPacket();
        initDataFullSyncPacket(ctx.dataPacket);
        fillDataFullSyncPacketWithDataTypes(ctx);
        fillDataFullSyncPacketWithFunctions(ctx);
        return ctx.dataPacket;
    }

    private void initDataFullSyncPacket(SDataFullSyncPacket dataPacket) {
        dataPacket.setTypedefs(new ArrayList<>());
        dataPacket.setEnums(new ArrayList<>());
        dataPacket.setStructures(new ArrayList<>());
        dataPacket.setClasses(new ArrayList<>());
        dataPacket.setFunctions(new ArrayList<>());
    }

    private void fillDataFullSyncPacketWithDataTypes(SyncContext ctx) {
        Iterator<DataType> dataTypes = sda.getProgram().getDataTypeManager().getAllDataTypes();
        while(dataTypes.hasNext()) {
            DataType dataType = dataTypes.next();
            if(dataType instanceof TypeDef) {
                dataTypeMapper.typedefTypeMapper.upsert(ctx, (TypeDef)dataType);
            } else if(dataType instanceof Enum) {
                dataTypeMapper.enumTypeMapper.upsert(ctx, (ghidra.program.model.data.Enum)dataType);
            } else if(dataType instanceof Structure) {
                dataTypeMapper.structureTypeMapper.upsert(ctx, (Structure)dataType);
            }
        }
    }

    private void fillDataFullSyncPacketWithFunctions(SyncContext ctx) {
        Iterator<Function> functions = sda.getProgram().getFunctionManager().getFunctions(true);
        int idx = 1000;
        while(functions.hasNext()) {
            if(--idx == 0)
                break;
            Function function = functions.next();
            functionMapper.upsert(ctx, function);
        }
    }
}
