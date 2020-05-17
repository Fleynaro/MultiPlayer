include "shared.thrift"

namespace java sda.ghidra.function
namespace cpp ghidra.function

typedef i64 Id

struct SFunctionRange {
	1: i32 minOffset,
	2: i32 maxOffset
}

struct SFunctionSignature {
	1: shared.STypeUnit returnType,
	2: list<shared.STypeUnit> arguments
}

struct SFunction {
	1: Id id,
	2: string name,
	3: string comment,
	4: list<string> argumentNames,
	5: SFunctionSignature signature
	6: list<SFunctionRange> ranges
}

service FunctionManagerService {
	list<SFunction> pull(),
	void push(1:list<SFunction> functions)
}