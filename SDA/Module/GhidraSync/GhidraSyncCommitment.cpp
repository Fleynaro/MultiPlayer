#include "GhidraSyncCommitment.h"

using namespace CE;
using namespace CE::Ghidra;

SyncCommitment::SyncCommitment(SQLite::Database* db, DataPacketTransferProvider* provider)
	: m_db(db), m_provider(provider)
{}

void SyncCommitment::upsert(IObject* obj) {
	m_upsertedObjs.push_back(obj);
}

void SyncCommitment::remove(IObject* obj) {
	m_removedObjs.push_back(obj);
}

void SyncCommitment::commit() {
	DataSyncPacket dataPacket;
	SyncContext ctx;
	SQLite::Transaction transaction(*m_db);

	ctx.m_syncId = createSyncRecord();
	ctx.m_dataPacket = &dataPacket;
	ctx.m_db = m_db;

	for (auto obj : m_upsertedObjs) {
		obj->getGhidraMapper()->upsert(&ctx, obj);
	}

	for (auto obj : m_removedObjs) {
		obj->getGhidraMapper()->remove(&ctx, obj);
	}

	transaction.commit();
	m_provider->sendDataPacket(&dataPacket);
}

int SyncCommitment::createSyncRecord() {
	using namespace std::chrono;
	SQLite::Statement query(*m_db, "INSERT INTO sda_ghidra_sync (date, type, comment, objectsCount) VALUES(?1, ?2, ?3, ?4)");
	query.bind(1, duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
	query.bind(2, 1);
	query.bind(3, "");
	query.bind(4, (int)m_upsertedObjs.size() + (int)m_removedObjs.size());
	query.exec();
	return (int)m_db->getLastInsertRowid();
}