#pragma once
#include "GhidraDataTypeMapper.h"
#include <Code/Type/FunctionSignature.h>

namespace CE::Ghidra
{
	class SignatureTypeMapper : public IMapper
	{
	public:
		SignatureTypeMapper(DataTypeMapper* dataTypeMapper);

		void load(packet::SDataFullSyncPacket* dataPacket) override;

		void upsert(SyncContext* ctx, IObject* obj) override;

		void remove(SyncContext* ctx, IObject* obj) override;

		datatype::SDataTypeSignature buildDesc(DataType::FunctionSignature* sig);

		void changeSignatureByDesc(DataType::FunctionSignature* sig, const datatype::SDataTypeSignature& sigDesc);

	private:
		DataTypeMapper* m_dataTypeMapper;
	};
};