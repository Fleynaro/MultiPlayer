namespace java sda.ghidra.shared
namespace cpp ghidra.shared

typedef i64 Id

struct STypeUnit {
	1: Id typeId,
	2: i32 pointerLvl,
	3: i32 arraySize
}