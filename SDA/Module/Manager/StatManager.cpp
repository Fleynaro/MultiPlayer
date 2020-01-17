#include "StatManager.h"
#include <Utility/Resource.h>
#include <Program.h>

void createGeneralStatDataBase(SQLite::Database& db)
{
	using namespace SQLite;

	SQL_Res res("SQL_CREATE_GENSTAT_DB", getProgram()->getModule());
	res.load();
	if (!res.isLoaded()) {
		//throw ex
		return;
	}
	db.exec(res.getData());
}

void CE::StatManager::initGeneralDB()
{
	auto filedb = FS::File(getProgramModule()->getDirectory(), "general_stat.db");
	bool filedbExisting = filedb.exists();
	m_general_db = new SQLite::Database(filedb.getFilename(), SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);

	if (!filedbExisting) {
		createGeneralStatDataBase(*m_general_db);
	}
}

SQLite::Database* CE::StatManager::openOrCreate_callBeforeDb(FS::File filedb) {
	bool filedbExisting = filedb.exists();
	auto db = new SQLite::Database(filedb.getFilename(), SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);

	if (!filedbExisting) {
		SQL_Res res("SQL_CREATE_CALLBEFORE_DB", getProgram()->getModule());
		res.load();
		if (!res.isLoaded()) {
			//throw ex
			return nullptr;
		}
		db->exec(res.getData());
	}
	return db;
}

SQLite::Database* CE::StatManager::openOrCreate_callAfterDb(FS::File filedb) {
	bool filedbExisting = filedb.exists();
	auto db = new SQLite::Database(filedb.getFilename(), SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);

	if (!filedbExisting) {
		SQL_Res res("SQL_CREATE_CALLAFTER_DB", getProgram()->getModule());
		res.load();
		if (!res.isLoaded()) {
			//throw ex
			return nullptr;
		}
		db->exec(res.getData());
	}
	return db;
}