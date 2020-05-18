package sda.sync.mappers;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import sda.Sda;
import sda.ghidra.datatype.SDataTypeEnum;
import sda.ghidra.datatype.SDataTypeEnumField;
import sda.ghidra.packet.SDataFullSyncPacket;
import sda.sync.IMapper;
import sda.sync.SyncContext;

import java.util.ArrayList;
import java.util.Iterator;

public class EnumTypeMapper implements IMapper {

    private Sda sda;
    public DataTypeMapper dataTypeMapper;

    public EnumTypeMapper(Sda sda, DataTypeMapper dataTypeMapper) {
        this.sda = sda;
        this.dataTypeMapper = dataTypeMapper;
    }

    @Override
    public void load(SDataFullSyncPacket dataPacket) {
        for(SDataTypeEnum enumDesc : dataPacket.getEnums()) {
            DataType type = dataTypeMapper.findDataTypeByGhidraId(enumDesc.getType().getId());
            changeEnumByDesc((EnumDataType)type, enumDesc);
        }
    }

    public void upsert(SyncContext ctx, EnumDataType type) {
        ctx.dataPacket.getEnums().add(buildDesc(type));
        dataTypeMapper.upsert(ctx, type);
    }

    private SDataTypeEnum buildDesc(EnumDataType Enum) {
        SDataTypeEnum enumDesc = new SDataTypeEnum();
        enumDesc.setType(dataTypeMapper.buildDesc(Enum));

        String[] fields = Enum.getNames();
        enumDesc.setFields(new ArrayList<>());
        for(String fieldName : fields) {
            SDataTypeEnumField enumField = new SDataTypeEnumField();
            enumField.setName(fieldName);
            enumField.setValue((int)Enum.getValue(fieldName));
            enumDesc.addToFields(enumField);
        }
        return enumDesc;
    }

    private void changeEnumByDesc(EnumDataType Enum, SDataTypeEnum enumDesc) {
        dataTypeMapper.changeTypeByDesc(Enum, enumDesc.getType());

        for(String fieldName : Enum.getNames()) {
            Enum.remove(fieldName);
        }

        for(SDataTypeEnumField field : enumDesc.getFields()) {
            Enum.add(field.getName(), field.getValue());
        }
    }
}
