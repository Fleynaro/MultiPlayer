#pragma once
#include "GhidraDataPacket.h"

namespace CE::Ghidra
{
	struct SyncContext
	{
		Id m_syncId;
		DataPacket* m_dataPacket;
	};

	class IMapper
	{
	public:
		virtual void load(DataPacket* dataPacket) = 0;
		virtual void upsert(SyncContext* ctx, IObject* obj) = 0;
		virtual void remove(SyncContext* ctx, IObject* obj) = 0;
	};
};