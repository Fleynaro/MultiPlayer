package sda.managers;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitorAdapter;
import sda.SdaType;
import sda.ghidra.datatype.*;
import sda.Sda;
import sda.ghidra.shared.STypeUnit;
import sda.util.ObjectHash;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class DataTypeManager extends AbstractManager {

    private static String dataTypeCategory = "SDA";

    public DataTypeManager(Sda sda) {
        super(sda);
    }

    public DataType findDataTypeById(long id, boolean returnDefType) {
        CategoryPath[] cats = {
                new CategoryPath("/"),
                new CategoryPath("/" + dataTypeCategory)
        };
        for(CategoryPath cat : cats)
        {
            DataType[] types = getDataTypeManager().getCategory(cat).getDataTypes();
            for (DataType type : types) {
                if(type instanceof Pointer || type instanceof Array)
                    continue;
                if (SdaType.getId(type) == id) {
                    return type;
                }
            }
        }
        return returnDefType ? new ByteDataType() : null;
    }

    public DataType getType(STypeUnit typeUnit) {
        return new SdaType(findDataTypeById(typeUnit.getTypeId(), true), typeUnit.getPointerLvl(), typeUnit.getArraySize()).getType();
    }

    private DataType create(SDataType typeDesc) {
        DataType dataType = null;

        switch(typeDesc.group)
        {
            case Enum: {
                dataType = new EnumDataType(getCategory(), typeDesc.getName(), typeDesc.getSize(), getDataTypeManager());
                break;
            }

            case Structure: {
                dataType = new StructureDataType(getCategory(), typeDesc.getName(), typeDesc.getSize(), getDataTypeManager());
                break;
            }
        }

        if(dataType != null) {
            setBaseInfo(dataType, typeDesc);
        }
        return dataType;
    }

    private void setBaseInfo(DataType dataType, SDataType typeDesc) {
        dataType.setDescription(typeDesc.getDesc());
        dataType.setSourceArchive(getDataTypeManager().getLocalSourceArchive());
    }

    private DataType changeOrCreate(SDataType typeDesc) {
        DataType dataType = findDataTypeById(typeDesc.getId(), false);
        if(dataType == null) {
            dataType = getDataTypeManager().addDataType(create(typeDesc), DataTypeConflictHandler.REPLACE_HANDLER);
        } else {
            try {
                dataType.setName(typeDesc.getName());
            } catch (InvalidNameException e) {
                e.printStackTrace();
            } catch (DuplicateNameException e) {
                e.printStackTrace();
            }
            dataType.setDescription(typeDesc.getDesc());
        }
        return dataType;
    }

    private boolean remove(SDataType typeDesc) {
        DataType dataType = findDataTypeById(typeDesc.getId(), false);
        if(dataType != null) {
            return getDataTypeManager().remove(dataType, new TaskMonitorAdapter(false));
        }
        return false;
    }

    public void change_commit(List<SDataType> types) {
        int id = getProgram().startTransaction("SDA: change data types");
        for(SDataType it : types) {
            if(it.getSize() == 0) {
                remove(it);
                continue;
            }
            changeOrCreate(it);
        }
        getProgram().endTransaction(id, true);
    }

    private void change(TypeDef typeDef, SDataTypeTypedef typedefDesc) {
        //impossible to change this kind of type
    }

    private TypeDef changeOrCreate(SDataTypeTypedef typedefDesc) {
        TypeDef dataType = (TypeDef)findDataTypeById(typedefDesc.getType().getId(), false);
        if(dataType == null) {
            DataType refDataType = findDataTypeById(typedefDesc.getRefType().getTypeId(), false);
            if(refDataType != null) {
                TypeDef typeDef = new TypedefDataType(
                        typedefDesc.getType().getName(),
                        new SdaType(refDataType, typedefDesc.getRefType().getPointerLvl(), typedefDesc.getRefType().getArraySize()).getType()
                );
                setBaseInfo(typeDef, typedefDesc.getType());
                dataType = (TypeDef)getDataTypeManager().addDataType(typeDef, DataTypeConflictHandler.REPLACE_HANDLER);
            }
        }
        return dataType;
    }

    public void changeTypedefs_commit(List<SDataTypeTypedef> typedefs) {
        int id = getProgram().startTransaction("SDA: change typedefs");
        for(SDataTypeTypedef typedef : typedefs) {
            changeOrCreate(typedef);
        }
        getProgram().endTransaction(id, true);
    }

    private void change(Structure structure, SDataTypeStructure structDesc) {
        structure.deleteAll();

        Iterator<SDataTypeStructureField> fields = structDesc.getFields().iterator();
        while(fields.hasNext()) {
            SDataTypeStructureField field = fields.next();
            DataType fieldDataType = findDataTypeById(field.getType().getTypeId(), true);
            SdaType sdaType = new SdaType(fieldDataType, field.getType().getPointerLvl(), field.getType().getArraySize());

            structure.insertAtOffset(field.getOffset(), sdaType.getType(), sdaType.getType().getLength(), field.getName(), field.getComment());
        }

        int byteCountToEnd = structDesc.getType().getSize() - structure.getLength();
        if(byteCountToEnd > 0) {
            if(byteCountToEnd > 1) {
                structure.add(new ArrayDataType(new Undefined1DataType(), byteCountToEnd - 1, 1), byteCountToEnd, "", "");
            }
            structure.add(new ByteDataType(), 1, "lastField", "end of the structure: not make this field as the undefined type");
        }
    }

    private Structure changeOrCreate(SDataTypeStructure structDesc) {
        Structure structure = (Structure) changeOrCreate(structDesc.type);
        if(structure == null)
            return null;
        change(structure, structDesc);
        return structure;
    }

    public void changeStructure_commit(List<SDataTypeStructure> structures) {
        int id = getProgram().startTransaction("SDA: change structures");
        for(SDataTypeStructure structure : structures) {
            changeOrCreate(structure);
        }
        getProgram().endTransaction(id, true);
    }

    private void change(Enum enumeration, SDataTypeEnum enumDesc) {
        for(String fieldName : enumeration.getNames()) {
            enumeration.remove(fieldName);
        }

        Iterator<SDataTypeEnumField> fields = enumDesc.getFields().iterator();
        while(fields.hasNext()) {
            SDataTypeEnumField field = fields.next();
            enumeration.add(field.getName(), field.getValue());
        }
    }

    private Enum changeOrCreate(SDataTypeEnum enumDesc) {
        Enum enumeration = (Enum) changeOrCreate(enumDesc.getType());
        if(enumeration == null)
            return null;
        change(enumeration, enumDesc);
        return enumeration;
    }

    public void changeEnum_commit(List<SDataTypeEnum> enumerations) {
        int id = getProgram().startTransaction("SDA: change enums");
        for(SDataTypeEnum enumeration : enumerations) {
            changeOrCreate(enumeration);
        }
        getProgram().endTransaction(id, true);
    }

    private ObjectHash getHash(SDataType typeDesc) {
        ObjectHash hash = new ObjectHash();
        hash.addValue(typeDesc.getName());
        hash.addValue(typeDesc.getDesc());
        return hash;
    }

    private ObjectHash getHash(SDataTypeTypedef typedefDesc) {
        ObjectHash hash = getHash(typedefDesc.getType());
        hash.addValue(typedefDesc.getRefType().getTypeId());
        hash.addValue(typedefDesc.getRefType().getPointerLvl());
        hash.addValue(typedefDesc.getRefType().getArraySize());
        return hash;
    }

    private ObjectHash getHash(SDataTypeStructure structDesc) {
        ObjectHash hash = getHash(structDesc.getType());
        for (SDataTypeStructureField field : structDesc.getFields()) {
            ObjectHash fieldHash = new ObjectHash();
            fieldHash.addValue(field.getOffset());
            fieldHash.addValue(field.getName());
            fieldHash.addValue(field.getComment());
            fieldHash.addValue(field.getType().getTypeId());
            fieldHash.addValue(field.getType().getPointerLvl());
            fieldHash.addValue(field.getType().getArraySize());
            hash.add(fieldHash);
        }
        return hash;
    }

    private ObjectHash getHash(SDataTypeEnum enumDesc) {
        ObjectHash hash = getHash(enumDesc.getType());
        for (SDataTypeEnumField field : enumDesc.getFields()) {
            ObjectHash fieldHash = new ObjectHash();
            fieldHash.addValue(field.getName());
            fieldHash.addValue(field.getValue());
            hash.add(fieldHash);
        }
        return hash;
    }

    private SDataTypeBase buildTypeBaseDesc(DataType dataType) {
        SDataTypeBase typeBaseDesc = new SDataTypeBase();
        typeBaseDesc.setId(SdaType.getId(dataType));
        typeBaseDesc.setName(dataType.getName());

        if(dataType instanceof Structure) {
            typeBaseDesc.setGroup(DataTypeGroup.Structure);
        } else if(dataType instanceof Enum) {
            typeBaseDesc.setGroup(DataTypeGroup.Enum);
        } else if(dataType instanceof TypeDef) {
            typeBaseDesc.setGroup(DataTypeGroup.Typedef);
        }

        return typeBaseDesc;
    }

    private SDataType buildTypeDesc(DataType dataType) {
        SDataType typeDesc = new SDataType();

        SDataTypeBase baseTypeDesc = buildTypeBaseDesc(dataType);
        typeDesc.setId(baseTypeDesc.getId());
        typeDesc.setName(baseTypeDesc.getName());
        typeDesc.setGroup(baseTypeDesc.getGroup());

        typeDesc.setDesc(dataType.getDescription());
        typeDesc.setSize(dataType.getLength());
        return typeDesc;
    }

    private SDataTypeTypedef buildDesc(TypeDef typeDef) {
        SDataTypeTypedef typedefDesc = new SDataTypeTypedef();
        typedefDesc.setType(buildTypeDesc(typeDef));
        typedefDesc.setRefType(new SdaType(typeDef.getBaseDataType()).getUnitType());
        return typedefDesc;
    }

    private SDataTypeEnum buildDesc(Enum enumeration) {
        SDataTypeEnum enumDesc = new SDataTypeEnum();
        enumDesc.setType(buildTypeDesc(enumeration));

        String[] fields = enumeration.getNames();
        enumDesc.fields = new ArrayList<>();
        for(String fieldName : fields) {
            SDataTypeEnumField enumField = new SDataTypeEnumField();
            enumField.setName(fieldName);
            enumField.setValue((int)enumeration.getValue(fieldName));
            enumDesc.addToFields(enumField);
        }
        return enumDesc;
    }

    private SDataTypeStructure buildDesc(Structure structure) {
        SDataTypeStructure structDesc = new SDataTypeStructure();
        structDesc.setType(buildTypeDesc(structure));
        DataTypeComponent[] components = structure.getDefinedComponents();
        structDesc.fields = new ArrayList<>();
        for(DataTypeComponent component : components) {
            SDataTypeStructureField field = new SDataTypeStructureField();
            field.setOffset(component.getOffset());
            field.setName(component.getFieldName());
            if(component.getComment() != null)
                field.setComment(component.getComment());
            else field.setComment("");
            field.setType(new SdaType(component.getDataType()).getUnitType());
            structDesc.addToFields(field);
        }
        return structDesc;
    }

    public List<SDataTypeBase> getAllTypes() {
        List<SDataTypeBase> result = new ArrayList<>();
        Iterator<DataType> dataTypes = getDataTypeManager().getAllDataTypes();
        while(dataTypes.hasNext()) {
            DataType dataType = dataTypes.next();
            if(dataType instanceof TypeDef || dataType instanceof Enum || dataType instanceof Structure) {
                result.add(buildTypeBaseDesc(dataType));
            }
        }
        return result;
    }

    public List<SDataTypeTypedef> getAllTypedefs(Map<Long, Long> hashmap) {
        List<SDataTypeTypedef> result = new ArrayList<>();
        Iterator<DataType> enums = getDataTypeManager().getAllDataTypes();
        while(enums.hasNext()) {
            DataType dataType = enums.next();
            if(dataType instanceof TypeDef) {
                TypeDef typedef = (TypeDef)dataType;
                Long hash = hashmap.get(SdaType.getId(typedef));
                SDataTypeTypedef desc = buildDesc(typedef);
                if (hash == null || hash.longValue() != getHash(desc).getHash()) {
                    result.add(desc);
                }
            }
        }
        return result;
    }

    public List<SDataTypeEnum> getAllEnums(Map<Long, Long> hashmap) {
        List<SDataTypeEnum> result = new ArrayList<>();
        Iterator<DataType> enums = getDataTypeManager().getAllDataTypes();
        while(enums.hasNext()) {
            DataType dataType = enums.next();
            if(dataType instanceof Enum) {
                Enum enumeration = (Enum)dataType;
                Long hash = hashmap.get(SdaType.getId(enumeration));
                SDataTypeEnum desc = buildDesc(enumeration);
                if (hash == null || hash.longValue() != getHash(desc).getHash()) {
                    result.add(desc);
                }
            }
        }
        return result;
    }

    public List<SDataTypeStructure> getAllStructures(Map<Long, Long> hashmap) {
        List<SDataTypeStructure> result = new ArrayList<>();
        Iterator<Structure> structures = getDataTypeManager().getAllStructures();
        while(structures.hasNext()) {
            Structure structure = structures.next();
            Long hash = hashmap.get(SdaType.getId(structure));
            SDataTypeStructure desc = buildDesc(structure);
            if (hash == null || hash.longValue() != getHash(desc).getHash()) {
                result.add(desc);
            }
        }
        return result;
    }

    private CategoryPath getCategory() {
        return new CategoryPath("/" + dataTypeCategory);
    }

    private ghidra.program.model.data.DataTypeManager getDataTypeManager() {
        return getProgram().getDataTypeManager();
    }
}
