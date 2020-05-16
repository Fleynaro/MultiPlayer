#pragma once
#include "GhidraAbstractMapper.h"

namespace CE::Ghidra
{
	class SyncCommitment
	{
	public:
		SyncCommitment(DataPacketTransferProvider* provider);

		void upsert(IObject* obj);

		void remove(IObject* obj);

		void commit();
	private:
		DataPacketTransferProvider* m_provider;
		std::list<IObject*> m_upsertedObjs;
		std::list<IObject*> m_removedObjs;
	};
};