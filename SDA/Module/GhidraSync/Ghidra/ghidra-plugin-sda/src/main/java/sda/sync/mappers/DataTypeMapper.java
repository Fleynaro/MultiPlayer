package sda.sync.mappers;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import sda.Sda;
import sda.ghidra.datatype.*;
import sda.ghidra.packet.SDataFullSyncPacket;
import sda.ghidra.shared.STypeUnit;
import sda.sync.IMapper;
import sda.sync.SyncContext;
import sda.util.ObjectHash;

import java.util.ArrayList;
import java.util.List;

public class DataTypeMapper implements IMapper {

    private Sda sda;
    public DataTypeManager dataTypeManager;
    public TypedefTypeMapper typedefTypeMapper;
    public EnumTypeMapper enumTypeMapper;
    public StructureTypeMapper structureTypeMapper;
    public ClassTypeMapper classTypeMapper;

    public DataTypeMapper(Sda sda, DataTypeManager dataTypeManager) {
        this.sda = sda;
        this.dataTypeManager = dataTypeManager;
        typedefTypeMapper = new TypedefTypeMapper(sda, this);
        enumTypeMapper = new EnumTypeMapper(sda, this);
        structureTypeMapper = new StructureTypeMapper(sda, this);
        classTypeMapper = new ClassTypeMapper(sda, structureTypeMapper);
    }

    @Override
    public void load(SDataFullSyncPacket dataPacket) {
        for(SDataTypeTypedef typedef : dataPacket.typedefs) {
            createTypeByDescIfNotExist(typedef.type);
        }

        for(SDataTypeEnum Enum : dataPacket.enums) {
            createTypeByDescIfNotExist(Enum.type);
        }

        for(SDataTypeStructure struct : dataPacket.structures) {
            createTypeByDescIfNotExist(struct.type);
        }

        for(SDataTypeClass Class : dataPacket.classes) {
            createTypeByDescIfNotExist(Class.structType.type);
        }

        typedefTypeMapper.load(dataPacket);
        enumTypeMapper.load(dataPacket);
        structureTypeMapper.load(dataPacket);
        classTypeMapper.load(dataPacket);
    }

    public void upsert(SyncContext ctx, DataType type) {
    }

    public SDataType buildDesc(DataType dataType) {
        SDataType typeDesc = new SDataType();

        typeDesc.setId(getGhidraId(dataType));
        typeDesc.setName(dataType.getName());

        if(dataType instanceof Structure) {
            typeDesc.setGroup(DataTypeGroup.Structure);
        } else if(dataType instanceof Enum) {
            typeDesc.setGroup(DataTypeGroup.Enum);
        } else if(dataType instanceof TypeDef) {
            typeDesc.setGroup(DataTypeGroup.Typedef);
        }

        typeDesc.setComment(dataType.getDescription());
        typeDesc.setSize(dataType.getLength());
        return typeDesc;
    }

    public STypeUnit buildTypeUnitDesc(DataType dataType) {
        STypeUnit typeUnitDesc = new STypeUnit();
        typeUnitDesc.setTypeId(getGhidraId(dataType));
        typeUnitDesc.setPointerLvls(new ArrayList<Short>());
        for(short lvl : getTypePointerLvls(dataType)) {
            typeUnitDesc.getPointerLvls().add(lvl);
        }
        return typeUnitDesc;
    }

    public DataType getTypeByDesc(STypeUnit desc) {
        DataType type = findDataTypeByGhidraId(desc.getTypeId());
        if(type == null) {
            return new ByteDataType();
        }

        for(short lvl : desc.getPointerLvls()) {
            if(lvl == 1) {
                type = new PointerDataType(type);
            } else {
                type = new ArrayDataType(type, lvl, type.getLength());
            }
        }
        return type;
    }

    public void changeTypeByDesc(DataType dataType, SDataType typeDesc) {
        try {
            dataType.setName(typeDesc.getName());
        } catch (InvalidNameException e) {
            e.printStackTrace();
        } catch (DuplicateNameException e) {
            e.printStackTrace();
        }
        dataType.setDescription(typeDesc.getComment());
    }

    public DataType findDataTypeByGhidraId(long id) {
        CategoryPath[] cats = {
                new CategoryPath("/"),
                new CategoryPath("/" + Sda.dataTypeCategory)
        };
        for(CategoryPath cat : cats)
        {
            DataType[] types = dataTypeManager.getCategory(cat).getDataTypes();
            for (DataType type : types) {
                if(type instanceof Pointer || type instanceof Array)
                    continue;
                if (getGhidraId(type) == id) {
                    return type;
                }
            }
        }
        return null;
    }

    private void createTypeByDescIfNotExist(SDataType typeDesc) {
        DataType type = findDataTypeByGhidraId(typeDesc.getId());
        if(type == null) {
            createTypeByDesc(typeDesc);
        }
    }

    private DataType createTypeByDesc(SDataType typeDesc) {
        DataType type = null;
        CategoryPath cat = new CategoryPath("/" + Sda.dataTypeCategory);
        switch(typeDesc.getGroup())
        {
            case Typedef:
                type = new TypedefDataType(cat, typeDesc.getName(), new ByteDataType(), dataTypeManager);
                break;
            case Enum:
                type = new EnumDataType(cat, typeDesc.getName(), typeDesc.getSize(), dataTypeManager);
                break;
            case Structure:
            case Class:
                type = new StructureDataType(cat, typeDesc.getName(), typeDesc.getSize(), dataTypeManager);
                break;
        }
        type.setDescription(typeDesc.getComment());
        return type;
    }

    private static List<Short> getTypePointerLvls(DataType dataType) {
        List<Short> ptr_levels = new ArrayList<Short>();
        if(dataType instanceof Pointer) {
            ptr_levels = getTypePointerLvls(((Pointer) dataType).getDataType());
            ptr_levels.add((short)1);
        } else if(dataType instanceof Array) {
            ptr_levels = getTypePointerLvls(((Array) dataType).getDataType());
            ptr_levels.add((short)((Array)dataType).getNumElements());
        }
        return ptr_levels;
    }

    private static String getTypeName(DataType dataType) {
        if(dataType == null) {
            return "byte";
        }
        if(dataType instanceof Array) {
            return getTypeName(((Array)dataType).getDataType());
        }
        if(dataType instanceof Pointer) {
            return getTypeName(((Pointer)dataType).getDataType());
        }
        return dataType.getName();
    }

    private static long getGhidraId(DataType dataType) {
        ObjectHash hash = new ObjectHash();
        hash.addValue(getTypeName(dataType));
        return hash.getHash();
    }
}
