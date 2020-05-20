include "shared.thrift"
include "datatype.thrift"
include "function.thrift"

namespace java sda.ghidra.packet
namespace cpp ghidra.packet

struct SDataLightSyncPacket {
	1: list<datatype.SDataType> types
}

struct SDataFullSyncPacket {
	1: list<datatype.SDataTypeTypedef> typedefs,
	2: list<datatype.SDataTypeClass> classes,
	3: list<datatype.SDataTypeStructure> structures,
	4: list<datatype.SDataTypeEnum> enums,
	5: list<datatype.SDataTypeSignature> signatures,
	6: list<function.SFunction> functions,
	7: list<shared.Id> removed_datatypes,
	8: list<shared.Id> removed_functions
}

service DataSyncPacketManagerService {
	SDataLightSyncPacket recieveLightSyncPacket(),
	void sendLightSyncPacket(1:SDataLightSyncPacket packet),

	SDataFullSyncPacket recieveFullSyncPacket(),
	void sendFullSyncPacket(1:SDataFullSyncPacket packet)
}