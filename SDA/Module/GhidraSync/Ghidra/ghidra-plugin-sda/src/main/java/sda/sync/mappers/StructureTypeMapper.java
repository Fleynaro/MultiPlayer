package sda.sync.mappers;

import ghidra.program.model.data.*;
import sda.Sda;
import sda.ghidra.datatype.SDataTypeStructure;
import sda.ghidra.datatype.SDataTypeStructureField;
import sda.ghidra.packet.SDataFullSyncPacket;
import sda.sync.IMapper;
import sda.sync.SyncContext;

import java.util.ArrayList;
import java.util.Iterator;

public class StructureTypeMapper implements IMapper {

    private Sda sda;
    public DataTypeMapper dataTypeMapper;

    public StructureTypeMapper(Sda sda, DataTypeMapper dataTypeMapper) {
        this.sda = sda;
        this.dataTypeMapper = dataTypeMapper;
    }

    @Override
    public void load(SDataFullSyncPacket dataPacket) {
        for(SDataTypeStructure structureDesc : dataPacket.getStructures()) {
            DataType type = dataTypeMapper.findDataTypeByGhidraId(structureDesc.getType().getId());
            changeStructureByDesc((StructureDataType)type, structureDesc);
        }
    }

    public void upsert(SyncContext ctx, StructureDataType type) {
        ctx.dataPacket.getStructures().add(buildDesc(type));
        dataTypeMapper.upsert(ctx, type);
    }

    public SDataTypeStructure buildDesc(StructureDataType Structure) {
        SDataTypeStructure StructureDesc = new SDataTypeStructure();
        StructureDesc.setType(dataTypeMapper.buildDesc(Structure));

        DataTypeComponent[] components = Structure.getDefinedComponents();
        StructureDesc.setFields(new ArrayList<>());
        for(DataTypeComponent component : components) {
            SDataTypeStructureField field = new SDataTypeStructureField();
            field.setOffset(component.getOffset());
            field.setName(component.getFieldName());
            if(component.getComment() != null)
                field.setComment(component.getComment());
            else field.setComment("");
            field.setType(dataTypeMapper.buildTypeUnitDesc(component.getDataType()));
            StructureDesc.addToFields(field);
        }
        return StructureDesc;
    }

    public void changeStructureByDesc(StructureDataType structure, SDataTypeStructure structDesc) {
        dataTypeMapper.changeTypeByDesc(structure, structDesc.getType());

        structure.deleteAll();
        for(SDataTypeStructureField field : structDesc.getFields()) {
            DataType type = dataTypeMapper.getTypeByDesc(field.getType());
            structure.insertAtOffset(field.getOffset(), type, type.getLength(), field.getName(), field.getComment());
        }

        int byteCountToEnd = structDesc.getType().getSize() - structure.getLength();
        if(byteCountToEnd > 0) {
            if(byteCountToEnd > 1) {
                structure.add(new ArrayDataType(new Undefined1DataType(), byteCountToEnd - 1, 1), byteCountToEnd, "", "");
            }
            structure.add(new ByteDataType(), 1, "lastField", "end of the structure: not make this field as the undefined type");
        }
    }
}
