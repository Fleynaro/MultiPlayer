include "shared.thrift"

namespace java sda.ghidra.datatype
namespace cpp ghidra.datatype

typedef i64 Id
typedef i64 Hash
typedef map<Id,Hash> HashMap

enum DataTypeGroup
{
	Simple,
	Enum,
	Structure,
	Typedef,
	Signature
}

struct SDataTypeBase {
	1: Id id,
	2: string name,
	3: DataTypeGroup group
}

struct SDataType {
	1: Id id,
	2: string name,
	3: string desc,
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
	list<SDataTypeBase> pull(),
	list<SDataTypeTypedef> pullTypedefs(1:HashMap hashmap),
	list<SDataTypeStructure> pullStructures(1:HashMap hashmap),
	list<SDataTypeEnum> pullEnums(1:HashMap hashmap)
	void push(1:list<SDataType> types),
	void pushTypedefs(1:list<SDataTypeTypedef> typedefs),
	void pushStructures(1:list<SDataTypeStructure> structures),
	void pushEnums(1:list<SDataTypeEnum> enums)
}