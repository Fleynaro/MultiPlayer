package sda.sync.mappers;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import sda.Sda;
import sda.ghidra.datatype.SDataTypeClass;
import sda.ghidra.packet.SDataFullSyncPacket;
import sda.sync.IMapper;
import sda.sync.SyncContext;

public class ClassTypeMapper implements IMapper {

    private Sda sda;
    public StructureTypeMapper structureTypeMapper;

    public ClassTypeMapper(Sda sda, StructureTypeMapper structureTypeMapper) {
        this.sda = sda;
        this.structureTypeMapper = structureTypeMapper;
    }

    @Override
    public void load(SDataFullSyncPacket dataPacket) {
        for(SDataTypeClass classDesc : dataPacket.getClasses()) {
            DataType type = structureTypeMapper.dataTypeMapper.findDataTypeByGhidraId(classDesc.getStructType().getType().getId());
            changeClassByDesc((StructureDataType)type, classDesc);
        }
    }

    public void upsert(SyncContext ctx, StructureDataType type) {
        ctx.dataPacket.getClasses().add(buildDesc(type));
        structureTypeMapper.dataTypeMapper.upsert(ctx, type);
    }

    private SDataTypeClass buildDesc(StructureDataType Class) {
        SDataTypeClass ClassDesc = new SDataTypeClass();
        ClassDesc.setStructType(structureTypeMapper.buildDesc(Class));

        return ClassDesc;
    }

    private void changeClassByDesc(StructureDataType Class, SDataTypeClass classDesc) {
        structureTypeMapper.changeStructureByDesc(Class, classDesc.getStructType());

    }
}
