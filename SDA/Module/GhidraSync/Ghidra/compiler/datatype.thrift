include "shared.thrift"

namespace java sda.ghidra.datatype
namespace cpp ghidra.datatype

typedef i64 Id

enum DataTypeGroup
{
	Simple,
	Enum,
	Structure,
	Class,
	Typedef,
	Signature
}

struct SDataType {
	1: Id id,
	2: string name,
	3: string comment,
	4: DataTypeGroup group,
	5: i32 size
}

struct SDataTypeStructureField {
	1: i32 offset,
	2: string name,
	3: string comment,
	4: shared.STypeUnit type
}

struct SDataTypeStructure {
	1: SDataType type,
	2: list<SDataTypeStructureField> fields
}

struct SDataTypeClass {
	1: SDataTypeStructure structType
}

struct SDataTypeEnumField {
	1: string name,
	2: i32 value
}

struct SDataTypeEnum {
	1: SDataType type,
	2: list<SDataTypeEnumField> fields
}

struct SDataTypeTypedef {
	1: SDataType type,
	2: shared.STypeUnit refType
}

service DataTypeManagerService {
	list<SDataType> pull(),
	list<SDataTypeTypedef> pullTypedefs(),
	list<SDataTypeStructure> pullStructures(),
	list<SDataTypeClass> pullClasses(),
	list<SDataTypeEnum> pullEnums(),
	void push(1:list<SDataType> types),
	void pushTypedefs(1:list<SDataTypeTypedef> typedefs),
	void pushStructures(1:list<SDataTypeStructure> structures),
	void pushClasses(1:list<SDataTypeClass> classes),
	void pushEnums(1:list<SDataTypeEnum> enums)
}