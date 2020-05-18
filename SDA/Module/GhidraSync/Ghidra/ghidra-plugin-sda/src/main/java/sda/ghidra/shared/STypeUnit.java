/**
 * Autogenerated by Thrift Compiler (0.12.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package sda.ghidra.shared;

@SuppressWarnings({"cast", "rawtypes", "serial", "unchecked", "unused"})
@javax.annotation.Generated(value = "Autogenerated by Thrift Compiler (0.12.0)", date = "2020-05-18")
public class STypeUnit implements org.apache.thrift.TBase<STypeUnit, STypeUnit._Fields>, java.io.Serializable, Cloneable, Comparable<STypeUnit> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("STypeUnit");

  private static final org.apache.thrift.protocol.TField TYPE_ID_FIELD_DESC = new org.apache.thrift.protocol.TField("typeId", org.apache.thrift.protocol.TType.I64, (short)1);
  private static final org.apache.thrift.protocol.TField POINTER_LVLS_FIELD_DESC = new org.apache.thrift.protocol.TField("pointerLvls", org.apache.thrift.protocol.TType.LIST, (short)2);

  private static final org.apache.thrift.scheme.SchemeFactory STANDARD_SCHEME_FACTORY = new STypeUnitStandardSchemeFactory();
  private static final org.apache.thrift.scheme.SchemeFactory TUPLE_SCHEME_FACTORY = new STypeUnitTupleSchemeFactory();

  public long typeId; // required
  public @org.apache.thrift.annotation.Nullable java.util.List<java.lang.Short> pointerLvls; // required

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    TYPE_ID((short)1, "typeId"),
    POINTER_LVLS((short)2, "pointerLvls");

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
        case 1: // TYPE_ID
          return TYPE_ID;
        case 2: // POINTER_LVLS
          return POINTER_LVLS;
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
  private static final int __TYPEID_ISSET_ID = 0;
  private byte __isset_bitfield = 0;
  public static final java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> metaDataMap;
  static {
    java.util.Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> tmpMap = new java.util.EnumMap<_Fields, org.apache.thrift.meta_data.FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.TYPE_ID, new org.apache.thrift.meta_data.FieldMetaData("typeId", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I64        , "Id")));
    tmpMap.put(_Fields.POINTER_LVLS, new org.apache.thrift.meta_data.FieldMetaData("pointerLvls", org.apache.thrift.TFieldRequirementType.DEFAULT, 
        new org.apache.thrift.meta_data.ListMetaData(org.apache.thrift.protocol.TType.LIST, 
            new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I16))));
    metaDataMap = java.util.Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(STypeUnit.class, metaDataMap);
  }

  public STypeUnit() {
  }

  public STypeUnit(
    long typeId,
    java.util.List<java.lang.Short> pointerLvls)
  {
    this();
    this.typeId = typeId;
    setTypeIdIsSet(true);
    this.pointerLvls = pointerLvls;
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public STypeUnit(STypeUnit other) {
    __isset_bitfield = other.__isset_bitfield;
    this.typeId = other.typeId;
    if (other.isSetPointerLvls()) {
      java.util.List<java.lang.Short> __this__pointerLvls = new java.util.ArrayList<java.lang.Short>(other.pointerLvls);
      this.pointerLvls = __this__pointerLvls;
    }
  }

  public STypeUnit deepCopy() {
    return new STypeUnit(this);
  }

  @Override
  public void clear() {
    setTypeIdIsSet(false);
    this.typeId = 0;
    this.pointerLvls = null;
  }

  public long getTypeId() {
    return this.typeId;
  }

  public STypeUnit setTypeId(long typeId) {
    this.typeId = typeId;
    setTypeIdIsSet(true);
    return this;
  }

  public void unsetTypeId() {
    __isset_bitfield = org.apache.thrift.EncodingUtils.clearBit(__isset_bitfield, __TYPEID_ISSET_ID);
  }

  /** Returns true if field typeId is set (has been assigned a value) and false otherwise */
  public boolean isSetTypeId() {
    return org.apache.thrift.EncodingUtils.testBit(__isset_bitfield, __TYPEID_ISSET_ID);
  }

  public void setTypeIdIsSet(boolean value) {
    __isset_bitfield = org.apache.thrift.EncodingUtils.setBit(__isset_bitfield, __TYPEID_ISSET_ID, value);
  }

  public int getPointerLvlsSize() {
    return (this.pointerLvls == null) ? 0 : this.pointerLvls.size();
  }

  @org.apache.thrift.annotation.Nullable
  public java.util.Iterator<java.lang.Short> getPointerLvlsIterator() {
    return (this.pointerLvls == null) ? null : this.pointerLvls.iterator();
  }

  public void addToPointerLvls(short elem) {
    if (this.pointerLvls == null) {
      this.pointerLvls = new java.util.ArrayList<java.lang.Short>();
    }
    this.pointerLvls.add(elem);
  }

  @org.apache.thrift.annotation.Nullable
  public java.util.List<java.lang.Short> getPointerLvls() {
    return this.pointerLvls;
  }

  public STypeUnit setPointerLvls(@org.apache.thrift.annotation.Nullable java.util.List<java.lang.Short> pointerLvls) {
    this.pointerLvls = pointerLvls;
    return this;
  }

  public void unsetPointerLvls() {
    this.pointerLvls = null;
  }

  /** Returns true if field pointerLvls is set (has been assigned a value) and false otherwise */
  public boolean isSetPointerLvls() {
    return this.pointerLvls != null;
  }

  public void setPointerLvlsIsSet(boolean value) {
    if (!value) {
      this.pointerLvls = null;
    }
  }

  public void setFieldValue(_Fields field, @org.apache.thrift.annotation.Nullable java.lang.Object value) {
    switch (field) {
    case TYPE_ID:
      if (value == null) {
        unsetTypeId();
      } else {
        setTypeId((java.lang.Long)value);
      }
      break;

    case POINTER_LVLS:
      if (value == null) {
        unsetPointerLvls();
      } else {
        setPointerLvls((java.util.List<java.lang.Short>)value);
      }
      break;

    }
  }

  @org.apache.thrift.annotation.Nullable
  public java.lang.Object getFieldValue(_Fields field) {
    switch (field) {
    case TYPE_ID:
      return getTypeId();

    case POINTER_LVLS:
      return getPointerLvls();

    }
    throw new java.lang.IllegalStateException();
  }

  /** Returns true if field corresponding to fieldID is set (has been assigned a value) and false otherwise */
  public boolean isSet(_Fields field) {
    if (field == null) {
      throw new java.lang.IllegalArgumentException();
    }

    switch (field) {
    case TYPE_ID:
      return isSetTypeId();
    case POINTER_LVLS:
      return isSetPointerLvls();
    }
    throw new java.lang.IllegalStateException();
  }

  @Override
  public boolean equals(java.lang.Object that) {
    if (that == null)
      return false;
    if (that instanceof STypeUnit)
      return this.equals((STypeUnit)that);
    return false;
  }

  public boolean equals(STypeUnit that) {
    if (that == null)
      return false;
    if (this == that)
      return true;

    boolean this_present_typeId = true;
    boolean that_present_typeId = true;
    if (this_present_typeId || that_present_typeId) {
      if (!(this_present_typeId && that_present_typeId))
        return false;
      if (this.typeId != that.typeId)
        return false;
    }

    boolean this_present_pointerLvls = true && this.isSetPointerLvls();
    boolean that_present_pointerLvls = true && that.isSetPointerLvls();
    if (this_present_pointerLvls || that_present_pointerLvls) {
      if (!(this_present_pointerLvls && that_present_pointerLvls))
        return false;
      if (!this.pointerLvls.equals(that.pointerLvls))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int hashCode = 1;

    hashCode = hashCode * 8191 + org.apache.thrift.TBaseHelper.hashCode(typeId);

    hashCode = hashCode * 8191 + ((isSetPointerLvls()) ? 131071 : 524287);
    if (isSetPointerLvls())
      hashCode = hashCode * 8191 + pointerLvls.hashCode();

    return hashCode;
  }

  @Override
  public int compareTo(STypeUnit other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = java.lang.Boolean.valueOf(isSetTypeId()).compareTo(other.isSetTypeId());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetTypeId()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.typeId, other.typeId);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = java.lang.Boolean.valueOf(isSetPointerLvls()).compareTo(other.isSetPointerLvls());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetPointerLvls()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.pointerLvls, other.pointerLvls);
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
    java.lang.StringBuilder sb = new java.lang.StringBuilder("STypeUnit(");
    boolean first = true;

    sb.append("typeId:");
    sb.append(this.typeId);
    first = false;
    if (!first) sb.append(", ");
    sb.append("pointerLvls:");
    if (this.pointerLvls == null) {
      sb.append("null");
    } else {
      sb.append(this.pointerLvls);
    }
    first = false;
    sb.append(")");
    return sb.toString();
  }

  public void validate() throws org.apache.thrift.TException {
    // check for required fields
    // check for sub-struct validity
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
      // it doesn't seem like you should have to do this, but java serialization is wacky, and doesn't call the default constructor.
      __isset_bitfield = 0;
      read(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(in)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private static class STypeUnitStandardSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    public STypeUnitStandardScheme getScheme() {
      return new STypeUnitStandardScheme();
    }
  }

  private static class STypeUnitStandardScheme extends org.apache.thrift.scheme.StandardScheme<STypeUnit> {

    public void read(org.apache.thrift.protocol.TProtocol iprot, STypeUnit struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // TYPE_ID
            if (schemeField.type == org.apache.thrift.protocol.TType.I64) {
              struct.typeId = iprot.readI64();
              struct.setTypeIdIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // POINTER_LVLS
            if (schemeField.type == org.apache.thrift.protocol.TType.LIST) {
              {
                org.apache.thrift.protocol.TList _list0 = iprot.readListBegin();
                struct.pointerLvls = new java.util.ArrayList<java.lang.Short>(_list0.size);
                short _elem1;
                for (int _i2 = 0; _i2 < _list0.size; ++_i2)
                {
                  _elem1 = iprot.readI16();
                  struct.pointerLvls.add(_elem1);
                }
                iprot.readListEnd();
              }
              struct.setPointerLvlsIsSet(true);
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

    public void write(org.apache.thrift.protocol.TProtocol oprot, STypeUnit struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      oprot.writeFieldBegin(TYPE_ID_FIELD_DESC);
      oprot.writeI64(struct.typeId);
      oprot.writeFieldEnd();
      if (struct.pointerLvls != null) {
        oprot.writeFieldBegin(POINTER_LVLS_FIELD_DESC);
        {
          oprot.writeListBegin(new org.apache.thrift.protocol.TList(org.apache.thrift.protocol.TType.I16, struct.pointerLvls.size()));
          for (short _iter3 : struct.pointerLvls)
          {
            oprot.writeI16(_iter3);
          }
          oprot.writeListEnd();
        }
        oprot.writeFieldEnd();
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class STypeUnitTupleSchemeFactory implements org.apache.thrift.scheme.SchemeFactory {
    public STypeUnitTupleScheme getScheme() {
      return new STypeUnitTupleScheme();
    }
  }

  private static class STypeUnitTupleScheme extends org.apache.thrift.scheme.TupleScheme<STypeUnit> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, STypeUnit struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol oprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet optionals = new java.util.BitSet();
      if (struct.isSetTypeId()) {
        optionals.set(0);
      }
      if (struct.isSetPointerLvls()) {
        optionals.set(1);
      }
      oprot.writeBitSet(optionals, 2);
      if (struct.isSetTypeId()) {
        oprot.writeI64(struct.typeId);
      }
      if (struct.isSetPointerLvls()) {
        {
          oprot.writeI32(struct.pointerLvls.size());
          for (short _iter4 : struct.pointerLvls)
          {
            oprot.writeI16(_iter4);
          }
        }
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, STypeUnit struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TTupleProtocol iprot = (org.apache.thrift.protocol.TTupleProtocol) prot;
      java.util.BitSet incoming = iprot.readBitSet(2);
      if (incoming.get(0)) {
        struct.typeId = iprot.readI64();
        struct.setTypeIdIsSet(true);
      }
      if (incoming.get(1)) {
        {
          org.apache.thrift.protocol.TList _list5 = new org.apache.thrift.protocol.TList(org.apache.thrift.protocol.TType.I16, iprot.readI32());
          struct.pointerLvls = new java.util.ArrayList<java.lang.Short>(_list5.size);
          short _elem6;
          for (int _i7 = 0; _i7 < _list5.size; ++_i7)
          {
            _elem6 = iprot.readI16();
            struct.pointerLvls.add(_elem6);
          }
        }
        struct.setPointerLvlsIsSet(true);
      }
    }
  }

  private static <S extends org.apache.thrift.scheme.IScheme> S scheme(org.apache.thrift.protocol.TProtocol proto) {
    return (org.apache.thrift.scheme.StandardScheme.class.equals(proto.getScheme()) ? STANDARD_SCHEME_FACTORY : TUPLE_SCHEME_FACTORY).getScheme();
  }
}

