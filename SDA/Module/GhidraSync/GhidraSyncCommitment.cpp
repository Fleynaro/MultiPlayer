#include "GhidraSyncCommitment.h"

using namespace CE;
using namespace CE::Ghidra;

SyncCommitment::SyncCommitment(DataPacketTransferProvider* provider)
	: m_provider(provider)
{}

void SyncCommitment::upsert(IObject* obj) {
	m_upsertedObjs.push_back(obj);
}

void SyncCommitment::remove(IObject* obj) {
	m_removedObjs.push_back(obj);
}

void SyncCommitment::commit() {
	DataPacket dataPacket;
	SyncContext ctx;
	ctx.m_syncId = 0;
	ctx.m_dataPacket = &dataPacket;

	for (auto obj : m_upsertedObjs) {
		obj->getGhidraMapper()->upsert(&ctx, obj);
	}

	for (auto obj : m_removedObjs) {
		obj->getGhidraMapper()->remove(&ctx, obj);
	}

	m_provider->sendDataPacket(&dataPacket);
}
