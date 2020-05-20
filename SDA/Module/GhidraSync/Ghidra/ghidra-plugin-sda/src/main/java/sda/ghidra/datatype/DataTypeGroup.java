/**
 * Autogenerated by Thrift Compiler (0.12.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package sda.ghidra.datatype;


@javax.annotation.Generated(value = "Autogenerated by Thrift Compiler (0.12.0)", date = "2020-05-20")
public enum DataTypeGroup implements org.apache.thrift.TEnum {
  Simple(0),
  Enum(1),
  Structure(2),
  Class(3),
  Typedef(4),
  Signature(5);

  private final int value;

  private DataTypeGroup(int value) {
    this.value = value;
  }

  /**
   * Get the integer value of this enum value, as defined in the Thrift IDL.
   */
  public int getValue() {
    return value;
  }

  /**
   * Find a the enum type by its integer value, as defined in the Thrift IDL.
   * @return null if the value is not found.
   */
  @org.apache.thrift.annotation.Nullable
  public static DataTypeGroup findByValue(int value) { 
    switch (value) {
      case 0:
        return Simple;
      case 1:
        return Enum;
      case 2:
        return Structure;
      case 3:
        return Class;
      case 4:
        return Typedef;
      case 5:
        return Signature;
      default:
        return null;
    }
  }
}
