package sda;

import ghidra.program.model.data.*;
import sda.ghidra.shared.STypeUnit;
import sda.util.ObjectHash;

public class SdaType
{
    private DataType dataType;
    private int pointerLvl = 0;
    private int arraySize = 0;

    public SdaType(DataType dataType)
    {
        this.dataType = dataType;
        countPointerLvl(dataType);
        countArraySize(dataType);
    }

    public SdaType(DataType dataType, int pointerLvl, int arraySize)
    {
        this.dataType = dataType;
        this.pointerLvl = pointerLvl;
        this.arraySize = arraySize;
    }

    public DataType getType() {
        DataType result = dataType;
        if (pointerLvl > 0) {
            for (int i = 0; i < pointerLvl; i++) {
                result = new PointerDataType(result);
            }
        }

        if (arraySize > 0) {
            result = new ArrayDataType(result, arraySize, result.getLength());
        }
        return result;
    }

    public long getId() {
        return getId(dataType);
    }

    public int getPointerLvl() {
        return pointerLvl;
    }

    public int getArraySize() {
        return arraySize;
    }

    public STypeUnit getUnitType() {
        STypeUnit typeUnitDesc = new STypeUnit();
        typeUnitDesc.setTypeId(getId());
        typeUnitDesc.setPointerLvl(getPointerLvl());
        typeUnitDesc.setArraySize(getArraySize());
        return typeUnitDesc;
    }

    private void countPointerLvl(DataType dataType) {
        if(dataType instanceof Pointer) {
            countPointerLvl(((Pointer)dataType).getDataType());
            pointerLvl++;
        }
    }

    private void countArraySize(DataType dataType) {
        if(dataType instanceof Array) {
            arraySize = ((Array)dataType).getNumElements();
        }
    }

    private static String getUnitName(DataType dataType) {
        if(dataType == null) {
            return "byte";
        }
        if(dataType instanceof Array) {
            return getUnitName(((Array)dataType).getDataType());
        }
        if(dataType instanceof Pointer) {
            return getUnitName(((Pointer)dataType).getDataType());
        }
        return dataType.getName();
    }

    public static long getId(DataType dataType) {
        ObjectHash hash = new ObjectHash();
        hash.addValue(getUnitName(dataType));
        return hash.getHash();
    }
}