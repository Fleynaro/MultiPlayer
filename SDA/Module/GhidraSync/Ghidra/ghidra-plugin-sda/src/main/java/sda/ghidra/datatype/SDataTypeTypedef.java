/**
 * Autogenerated by Thrift Compiler (0.12.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package sda.ghidra.datatype;

@SuppressWarnings({"cast", "rawtypes", "serial", "unchecked", "unused"})
@javax.annotation.Generated(value = "Autogenerated by Thrift Compiler (0.12.0)", date = "2020-01-08")
public class SDataTypeTypedef implements org.apache.thrift.TBase<SDataTypeTypedef, SDataTypeTypedef._Fields>, java.io.Serializable, Cloneable, Comparable<SDataTypeTypedef> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("SDataTypeTypedef");

  private static final org.apache.thrift.protocol.TField TYPE_FIELD_DESC = new org.apache.thrift.protocol.TField("type", org.apache.thrift.protocol.TType.STRUCT, (short)1);
  private static final org.apache.thrift.protocol.TField REF_TYPE_FIELD_DESC = new org.apache.thrift.protocol.TField("refType", org.apache.thrift.protocol.TType.STRUCT, (short)2);

  private static final org.apache.thrift.scheme.SchemeFactory STANDARD_SCHEME_FACTORY = new SDataTypeTypedefStandardSchemeFactory();
  private static final org.apache.thrift.scheme.SchemeFactory TUPLE_SCHEME_FACTORY = new SDataTypeTypedefTupleSchemeFactory();

  public @org.apache.thrift.annotation.Nullable SDataType type; // required
  public @org.apache.thrift.annotation.Nullable sda.ghidra.shared.STypeUnit refType; // required

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    TYPE((short)1, "type"),
    REF_TYPE((short)2, "refType");

    private static final java.util.Map<java.lang.String, _Fields> byName = new java.util.HashMap<java.lang.String, _Fields>();

    static {
      for (_Fields field : java.util.EnumSet.allOf(_Fields.class)) {
        byName.put(field.getFieldName(), field);
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, or null if its not found.
     */
    @org.apache.thrift.annotation.Nullable
    public static _Fields findByThriftId(int fieldId) {
      switch(fieldId) {
        case 1: // TYPE
          return TYPE;
        case 2: // REF_TYPE
          return REF_TYPE;
        default:
          return null;
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, throwing an exception
     * if it is not found.
     */
    public static _Fields findByThriftIdOrThrow(int fieldId) {
      _Fields fields = findByThriftId(fieldId);
      if (fields == null) throw new java.lang.IllegalArgumentException("Field " + fieldId + " doesn't exist!");
      return fields;
    }

    /**
     * Find the _Fields constant that matches name, or null if its not found.
     */
    @org.apache.thrift.annotation.Nullable
    public static _Fields findByName(java.lang.String name) {
      return byName.get(name);
    }

    private final short _thriftId;
    private final java.lang.String _fieldName;

    _Fields(short thriftId, java.lang.String fieldName) {
      _thriftId = thriftId;
      _fieldName = fieldName;
    }

    public short getThriftFieldId() {
      return _thriftId;
    }

    public java.lang.String getFieldName() {
      return _fieldName;
    }
  }

  // isset id assignments
  public static final java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> metaDataMap;
  static {
    java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> tmpMap = new java.util.EnumMap<_Fields, org.apache.thrift.meta_data.FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.TYPE, new org.apache.thrift.meta_data.FieldMetaData("type", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.StructMetaData(org.apache.thrift.protocol.TType.STRUCT, SDataType.class)));
    tmpMap.put(_Fields.REF_TYPE, new org.apache.thrift.meta_data.FieldMetaData("refType", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.StructMetaData(org.apache.thrift.protocol.TType.STRUCT, sda.ghidra.shared.STypeUnit.class)));
    metaDataMap = java.util.Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(SDataTypeTypedef.class, metaDataMap);
  }

  public SDataTypeTypedef() {
  }

  public SDataTypeTypedef(
    SDataType type,
    sda.ghidra.shared.STypeUnit refType)
  {
    this();
    this.type = type;
    this.refType = refType;
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public SDataTypeTypedef(SDataTypeTypedef other) {
    if (other.isSetType()) {
      this.type = new SDataType(other.type);
    }
    if (other.isSetRefType()) {
      this.refType = new sda.ghidra.shared.STypeUnit(other.refType);
    }
  }

  public SDataTypeTypedef deepCopy() {
    return new SDataTypeTypedef(this);
  }

  @Override
  public void clear() {
    this.type = null;
    this.refType = null;
  }

  @org.apache.thrift.annotation.Nullable
  public SDataType getType() {
    return this.type;
  }

  public SDataTypeTypedef setType(@org.apache.thrift.annotation.Nullable SDataType type) {
    this.type = type;
    return this;
  }

  public void unsetType() {
    this.type = null;
  }

  /** Returns true if field type is set (has been assigned a value) and false otherwise */
  public boolean isSetType() {
    return this.type != null;
  }

  public void setTypeIsSet(boolean value) {
    if (!value) {
      this.type = null;
    }
  }

  @org.apache.thrift.annotation.Nullable
  public sda.ghidra.shared.STypeUnit getRefType() {
    return this.refType;
  }

  public SDataTypeTypedef setRefType(@org.apache.thrift.annotation.Nullable sda.ghidra.shared.STypeUnit refType) {
    this.refType = refType;
    return this;
  }

  public void unsetRefType() {
    this.refType = null;
  }

  /** Returns true if field refType is set (has been assigned a value) and false otherwise */
  public boolean isSetRefType() {
    return this.refType != null;
  }

  public void setRefTypeIsSet(boolean value) {
    if (!value) {
      this.refType = null;
    }
  }

  public void setFieldValue(_Fields field, @org.apache.thrift.annotation.Nullable java.lang.Object value) {
    switch (field) {
    case TYPE:
      if (value == null) {
        unsetType();
      } else {
        setType((SDataType)value);
      }
      break;

    case REF_TYPE:
      if (value == null) {
        unsetRefType();
      } else {
        setRefType((sda.ghidra.shared.STypeUnit)value);
      }
      break;

    }
  }

  @org.apache.thrift.annotation.Nullable
  public java.lang.Object getFieldValue(_Fields field) {
    switch (field) {
    case TYPE:
      return getType();

    case REF_TYPE:
      return getRefType();

    }
    throw new java.lang.IllegalStateException();
  }

  /** Returns true if field corresponding to fieldID is set (has been assigned a value) and false otherwise */
  public boolean isSet(_Fields field) {
    if (field == null) {
      throw new java.lang.IllegalArgumentException();
    }

    switch (field) {
    case TYPE:
      return isSetType();
    case REF_TYPE:
      return isSetRefType();
    }
    throw new java.lang.IllegalStateException();
  }

  @Override
  public boolean equals(java.lang.Object that) {
    if (that == null)
      return false;
    if (that instanceof SDataTypeTypedef)
      return this.equals((SDataTypeTypedef)that);
    return false;
  }

  public boolean equals(SDataTypeTypedef that) {
    if (that == null)
      return false;
    if (this == that)
      return true;

    boolean this_present_type = true && this.isSetType();
    boolean that_present_type = true && that.isSetType();
    if (this_present_type || that_present_type) {
      if (!(this_present_type && that_present_type))
        return false;
      if (!this.type.equals(that.type))
        return false;
    }

    boolean this_present_refType = true && this.isSetRefType();
    boolean that_present_refType = true && that.isSetRefType();
    if (this_present_refType || that_present_refType) {
      if (!(this_present_refType && that_present_refType))
        return false;
      if (!this.refType.equals(that.refType))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 1;

    hashCode = hashCode * 8191 + ((isSetType()) ? 131071 : 524287);
    if (isSetType())
      hashCode = hashCode * 8191 + type.hashCode();

    hashCode = hashCode * 8191 + ((isSetRefType()) ? 131071 : 524287);
    if (isSetRefType())
      hashCode = hashCode * 8191 + refType.hashCode();

    return hashCode;
  }

  @Override
  public int compareTo(SDataTypeTypedef other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = java.lang.Boolean.valueOf(isSetType()).compareTo(other.isSetType());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetType()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.type, other.type);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.valueOf(isSetRefType()).compareTo(other.isSetRefType());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetRefType()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.refType, other.refType);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    return 0;
  }

  @org.apache.thrift.annotation.Nullable
  public _Fields fieldForId(int fieldId) {
    return _Fields.findByThriftId(fieldId);
  }

  public void read(org.apache.thrift.protocol.TProtocol iprot) throws org.apache.thrift.TException {
    scheme(iprot).read(iprot, this);
  }

  public void write(org.apache.thrift.protocol.TProtocol oprot) throws org.apache.thrift.TException {
    scheme(oprot).write(oprot, this);
  }

  @Override
  public java.lang.String toString() {
    java.lang.StringBuilder sb = new java.lang.StringBuilder("SDataTypeTypedef(");
    boolean first = true;

    sb.append("type:");
    if (this.type == null) {
      sb.append("null");
    } else {
      sb.append(this.type);
    }
    first = false;
    if (!first) sb.append(", ");
    sb.append("refType:");
    if (this.refType == null) {
      sb.append("null");
    } else {
      sb.append(this.refType);
    }
    first = false;
    sb.append(")");
    return sb.toString();
  }

  public void validate() throws org.apache.thrift.TException {
    // check for required fields
    // check for sub-struct validity
    if (type != null) {
      type.validate();
    }
    if (refType != null) {
      refType.validate();
    }
  }

  private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
    try {
      write(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(out)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private void readObject(java.io.ObjectInputStream in) throws java.io.IOException, java.lang.ClassNotFoundException {
    try {
      read(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(in)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private static class SDataTypeTypedefStandardSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    public SDataTypeTypedefStandardScheme getScheme() {
      return new SDataTypeTypedefStandardScheme();
    }
  }

  private static class SDataTypeTypedefStandardScheme extends org.apache.thrift.scheme.StandardScheme<SDataTypeTypedef> {

    public void read(org.apache.thrift.protocol.TProtocol iprot, SDataTypeTypedef struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // TYPE
            if (schemeField.type == org.apache.thrift.protocol.TType.STRUCT) {
              struct.type = new SDataType();
              struct.type.read(iprot);
              struct.setTypeIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // REF_TYPE
            if (schemeField.type == org.apache.thrift.protocol.TType.STRUCT) {
              struct.refType = new sda.ghidra.shared.STypeUnit();
              struct.refType.read(iprot);
              struct.setRefTypeIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          default:
            org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
        }
        iprot.readFieldEnd();
      }
      iprot.readStructEnd();

      // check for required fields of primitive type, which can't be checked in the validate method
      struct.validate();
    }

    public void write(org.apache.thrift.protocol.TProtocol oprot, SDataTypeTypedef struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      if (struct.type != null) {
        oprot.writeFieldBegin(TYPE_FIELD_DESC);
        struct.type.write(oprot);
        oprot.writeFieldEnd();
      }
      if (struct.refType != null) {
        oprot.writeFieldBegin(REF_TYPE_FIELD_DESC);
        struct.refType.write(oprot);
        oprot.writeFieldEnd();
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class SDataTypeTypedefTupleSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    public SDataTypeTypedefTupleScheme getScheme() {
      return new SDataTypeTypedefTupleScheme();
    }
  }

  private static class SDataTypeTypedefTupleScheme extends org.apache.thrift.scheme.TupleScheme<SDataTypeTypedef> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, SDataTypeTypedef struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol oprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet optionals = new java.util.BitSet();
      if (struct.isSetType()) {
        optionals.set(0);
      }
      if (struct.isSetRefType()) {
        optionals.set(1);
      }
      oprot.writeBitSet(optionals, 2);
      if (struct.isSetType()) {
        struct.type.write(oprot);
      }
      if (struct.isSetRefType()) {
        struct.refType.write(oprot);
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, SDataTypeTypedef struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol iprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet incoming = iprot.readBitSet(2);
      if (incoming.get(0)) {
        struct.type = new SDataType();
        struct.type.read(iprot);
        struct.setTypeIsSet(true);
      }
      if (incoming.get(1)) {
        struct.refType = new sda.ghidra.shared.STypeUnit();
        struct.refType.read(iprot);
        struct.setRefTypeIsSet(true);
      }
    }
  }

  private static <S extends org.apache.thrift.scheme.IScheme> S scheme(org.apache.thrift.protocol.TProtocol proto) {
    return (org.apache.thrift.scheme.StandardScheme.class.equals(proto.getScheme()) ? STANDARD_SCHEME_FACTORY : TUPLE_SCHEME_FACTORY).getScheme();
  }
}

