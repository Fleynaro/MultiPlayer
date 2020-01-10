/**
 * Autogenerated by Thrift Compiler (0.12.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package sda.ghidra.function;

@SuppressWarnings({"cast", "rawtypes", "serial", "unchecked", "unused"})
@javax.annotation.Generated(value = "Autogenerated by Thrift Compiler (0.12.0)", date = "2020-01-08")
public class SFunctionSignature implements org.apache.thrift.TBase<SFunctionSignature, SFunctionSignature._Fields>, java.io.Serializable, Cloneable, Comparable<SFunctionSignature> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("SFunctionSignature");

  private static final org.apache.thrift.protocol.TField RETURN_TYPE_FIELD_DESC = new org.apache.thrift.protocol.TField("returnType", org.apache.thrift.protocol.TType.STRUCT, (short)1);
  private static final org.apache.thrift.protocol.TField ARGUMENTS_FIELD_DESC = new org.apache.thrift.protocol.TField("arguments", org.apache.thrift.protocol.TType.LIST, (short)2);

  private static final org.apache.thrift.scheme.SchemeFactory STANDARD_SCHEME_FACTORY = new SFunctionSignatureStandardSchemeFactory();
  private static final org.apache.thrift.scheme.SchemeFactory TUPLE_SCHEME_FACTORY = new SFunctionSignatureTupleSchemeFactory();

  public @org.apache.thrift.annotation.Nullable sda.ghidra.shared.STypeUnit returnType; // required
  public @org.apache.thrift.annotation.Nullable java.util.List<sda.ghidra.shared.STypeUnit> arguments; // required

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    RETURN_TYPE((short)1, "returnType"),
    ARGUMENTS((short)2, "arguments");

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
        case 1: // RETURN_TYPE
          return RETURN_TYPE;
        case 2: // ARGUMENTS
          return ARGUMENTS;
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
    tmpMap.put(_Fields.RETURN_TYPE, new org.apache.thrift.meta_data.FieldMetaData("returnType", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.StructMetaData(org.apache.thrift.protocol.TType.STRUCT, sda.ghidra.shared.STypeUnit.class)));
    tmpMap.put(_Fields.ARGUMENTS, new org.apache.thrift.meta_data.FieldMetaData("arguments", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.ListMetaData(org.apache.thrift.protocol.TType.LIST, 
            new org.apache.thrift.meta_data.StructMetaData(org.apache.thrift.protocol.TType.STRUCT, sda.ghidra.shared.STypeUnit.class))));
    metaDataMap = java.util.Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(SFunctionSignature.class, metaDataMap);
  }

  public SFunctionSignature() {
  }

  public SFunctionSignature(
    sda.ghidra.shared.STypeUnit returnType,
    java.util.List<sda.ghidra.shared.STypeUnit> arguments)
  {
    this();
    this.returnType = returnType;
    this.arguments = arguments;
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public SFunctionSignature(SFunctionSignature other) {
    if (other.isSetReturnType()) {
      this.returnType = new sda.ghidra.shared.STypeUnit(other.returnType);
    }
    if (other.isSetArguments()) {
      java.util.List<sda.ghidra.shared.STypeUnit> __this__arguments = new java.util.ArrayList<sda.ghidra.shared.STypeUnit>(other.arguments.size());
      for (sda.ghidra.shared.STypeUnit other_element : other.arguments) {
        __this__arguments.add(new sda.ghidra.shared.STypeUnit(other_element));
      }
      this.arguments = __this__arguments;
    }
  }

  public SFunctionSignature deepCopy() {
    return new SFunctionSignature(this);
  }

  @Override
  public void clear() {
    this.returnType = null;
    this.arguments = null;
  }

  @org.apache.thrift.annotation.Nullable
  public sda.ghidra.shared.STypeUnit getReturnType() {
    return this.returnType;
  }

  public SFunctionSignature setReturnType(@org.apache.thrift.annotation.Nullable sda.ghidra.shared.STypeUnit returnType) {
    this.returnType = returnType;
    return this;
  }

  public void unsetReturnType() {
    this.returnType = null;
  }

  /** Returns true if field returnType is set (has been assigned a value) and false otherwise */
  public boolean isSetReturnType() {
    return this.returnType != null;
  }

  public void setReturnTypeIsSet(boolean value) {
    if (!value) {
      this.returnType = null;
    }
  }

  public int getArgumentsSize() {
    return (this.arguments == null) ? 0 : this.arguments.size();
  }

  @org.apache.thrift.annotation.Nullable
  public java.util.Iterator<sda.ghidra.shared.STypeUnit> getArgumentsIterator() {
    return (this.arguments == null) ? null : this.arguments.iterator();
  }

  public void addToArguments(sda.ghidra.shared.STypeUnit elem) {
    if (this.arguments == null) {
      this.arguments = new java.util.ArrayList<sda.ghidra.shared.STypeUnit>();
    }
    this.arguments.add(elem);
  }

  @org.apache.thrift.annotation.Nullable
  public java.util.List<sda.ghidra.shared.STypeUnit> getArguments() {
    return this.arguments;
  }

  public SFunctionSignature setArguments(@org.apache.thrift.annotation.Nullable java.util.List<sda.ghidra.shared.STypeUnit> arguments) {
    this.arguments = arguments;
    return this;
  }

  public void unsetArguments() {
    this.arguments = null;
  }

  /** Returns true if field arguments is set (has been assigned a value) and false otherwise */
  public boolean isSetArguments() {
    return this.arguments != null;
  }

  public void setArgumentsIsSet(boolean value) {
    if (!value) {
      this.arguments = null;
    }
  }

  public void setFieldValue(_Fields field, @org.apache.thrift.annotation.Nullable java.lang.Object value) {
    switch (field) {
    case RETURN_TYPE:
      if (value == null) {
        unsetReturnType();
      } else {
        setReturnType((sda.ghidra.shared.STypeUnit)value);
      }
      break;

    case ARGUMENTS:
      if (value == null) {
        unsetArguments();
      } else {
        setArguments((java.util.List<sda.ghidra.shared.STypeUnit>)value);
      }
      break;

    }
  }

  @org.apache.thrift.annotation.Nullable
  public java.lang.Object getFieldValue(_Fields field) {
    switch (field) {
    case RETURN_TYPE:
      return getReturnType();

    case ARGUMENTS:
      return getArguments();

    }
    throw new java.lang.IllegalStateException();
  }

  /** Returns true if field corresponding to fieldID is set (has been assigned a value) and false otherwise */
  public boolean isSet(_Fields field) {
    if (field == null) {
      throw new java.lang.IllegalArgumentException();
    }

    switch (field) {
    case RETURN_TYPE:
      return isSetReturnType();
    case ARGUMENTS:
      return isSetArguments();
    }
    throw new java.lang.IllegalStateException();
  }

  @Override
  public boolean equals(java.lang.Object that) {
    if (that == null)
      return false;
    if (that instanceof SFunctionSignature)
      return this.equals((SFunctionSignature)that);
    return false;
  }

  public boolean equals(SFunctionSignature that) {
    if (that == null)
      return false;
    if (this == that)
      return true;

    boolean this_present_returnType = true && this.isSetReturnType();
    boolean that_present_returnType = true && that.isSetReturnType();
    if (this_present_returnType || that_present_returnType) {
      if (!(this_present_returnType && that_present_returnType))
        return false;
      if (!this.returnType.equals(that.returnType))
        return false;
    }

    boolean this_present_arguments = true && this.isSetArguments();
    boolean that_present_arguments = true && that.isSetArguments();
    if (this_present_arguments || that_present_arguments) {
      if (!(this_present_arguments && that_present_arguments))
        return false;
      if (!this.arguments.equals(that.arguments))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 1;

    hashCode = hashCode * 8191 + ((isSetReturnType()) ? 131071 : 524287);
    if (isSetReturnType())
      hashCode = hashCode * 8191 + returnType.hashCode();

    hashCode = hashCode * 8191 + ((isSetArguments()) ? 131071 : 524287);
    if (isSetArguments())
      hashCode = hashCode * 8191 + arguments.hashCode();

    return hashCode;
  }

  @Override
  public int compareTo(SFunctionSignature other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = java.lang.Boolean.valueOf(isSetReturnType()).compareTo(other.isSetReturnType());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetReturnType()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.returnType, other.returnType);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.valueOf(isSetArguments()).compareTo(other.isSetArguments());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetArguments()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.arguments, other.arguments);
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
    java.lang.StringBuilder sb = new java.lang.StringBuilder("SFunctionSignature(");
    boolean first = true;

    sb.append("returnType:");
    if (this.returnType == null) {
      sb.append("null");
    } else {
      sb.append(this.returnType);
    }
    first = false;
    if (!first) sb.append(", ");
    sb.append("arguments:");
    if (this.arguments == null) {
      sb.append("null");
    } else {
      sb.append(this.arguments);
    }
    first = false;
    sb.append(")");
    return sb.toString();
  }

  public void validate() throws org.apache.thrift.TException {
    // check for required fields
    // check for sub-struct validity
    if (returnType != null) {
      returnType.validate();
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

  private static class SFunctionSignatureStandardSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    public SFunctionSignatureStandardScheme getScheme() {
      return new SFunctionSignatureStandardScheme();
    }
  }

  private static class SFunctionSignatureStandardScheme extends org.apache.thrift.scheme.StandardScheme<SFunctionSignature> {

    public void read(org.apache.thrift.protocol.TProtocol iprot, SFunctionSignature struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // RETURN_TYPE
            if (schemeField.type == org.apache.thrift.protocol.TType.STRUCT) {
              struct.returnType = new sda.ghidra.shared.STypeUnit();
              struct.returnType.read(iprot);
              struct.setReturnTypeIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // ARGUMENTS
            if (schemeField.type == org.apache.thrift.protocol.TType.LIST) {
              {
                org.apache.thrift.protocol.TList _list0 = iprot.readListBegin();
                struct.arguments = new java.util.ArrayList<sda.ghidra.shared.STypeUnit>(_list0.size);
                @org.apache.thrift.annotation.Nullable sda.ghidra.shared.STypeUnit _elem1;
                for (int _i2 = 0; _i2 < _list0.size; ++_i2)
                {
                  _elem1 = new sda.ghidra.shared.STypeUnit();
                  _elem1.read(iprot);
                  struct.arguments.add(_elem1);
                }
                iprot.readListEnd();
              }
              struct.setArgumentsIsSet(true);
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

    public void write(org.apache.thrift.protocol.TProtocol oprot, SFunctionSignature struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      if (struct.returnType != null) {
        oprot.writeFieldBegin(RETURN_TYPE_FIELD_DESC);
        struct.returnType.write(oprot);
        oprot.writeFieldEnd();
      }
      if (struct.arguments != null) {
        oprot.writeFieldBegin(ARGUMENTS_FIELD_DESC);
        {
          oprot.writeListBegin(new org.apache.thrift.protocol.TList(org.apache.thrift.protocol.TType.STRUCT, struct.arguments.size()));
          for (sda.ghidra.shared.STypeUnit _iter3 : struct.arguments)
          {
            _iter3.write(oprot);
          }
          oprot.writeListEnd();
        }
        oprot.writeFieldEnd();
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class SFunctionSignatureTupleSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    public SFunctionSignatureTupleScheme getScheme() {
      return new SFunctionSignatureTupleScheme();
    }
  }

  private static class SFunctionSignatureTupleScheme extends org.apache.thrift.scheme.TupleScheme<SFunctionSignature> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, SFunctionSignature struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol oprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet optionals = new java.util.BitSet();
      if (struct.isSetReturnType()) {
        optionals.set(0);
      }
      if (struct.isSetArguments()) {
        optionals.set(1);
      }
      oprot.writeBitSet(optionals, 2);
      if (struct.isSetReturnType()) {
        struct.returnType.write(oprot);
      }
      if (struct.isSetArguments()) {
        {
          oprot.writeI32(struct.arguments.size());
          for (sda.ghidra.shared.STypeUnit _iter4 : struct.arguments)
          {
            _iter4.write(oprot);
          }
        }
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, SFunctionSignature struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol iprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet incoming = iprot.readBitSet(2);
      if (incoming.get(0)) {
        struct.returnType = new sda.ghidra.shared.STypeUnit();
        struct.returnType.read(iprot);
        struct.setReturnTypeIsSet(true);
      }
      if (incoming.get(1)) {
        {
          org.apache.thrift.protocol.TList _list5 = new org.apache.thrift.protocol.TList(org.apache.thrift.protocol.TType.STRUCT, iprot.readI32());
          struct.arguments = new java.util.ArrayList<sda.ghidra.shared.STypeUnit>(_list5.size);
          @org.apache.thrift.annotation.Nullable sda.ghidra.shared.STypeUnit _elem6;
          for (int _i7 = 0; _i7 < _list5.size; ++_i7)
          {
            _elem6 = new sda.ghidra.shared.STypeUnit();
            _elem6.read(iprot);
            struct.arguments.add(_elem6);
          }
        }
        struct.setArgumentsIsSet(true);
      }
    }
  }

  private static <S extends org.apache.thrift.scheme.IScheme> S scheme(org.apache.thrift.protocol.TProtocol proto) {
    return (org.apache.thrift.scheme.StandardScheme.class.equals(proto.getScheme()) ? STANDARD_SCHEME_FACTORY : TUPLE_SCHEME_FACTORY).getScheme();
  }
}

