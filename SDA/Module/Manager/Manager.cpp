#include "Manager.h"
#include <GhidraSync/GhidraSync.h>
#include <FunctionTag/FunctionTag.h>

#include <Utility/Resource.h>
#include <Program.h>
void createGeneralDataBase(SQLite::Database& db)
{
	using namespace SQLite;
	
	SQL_Res res("SQL_CREATE_GEN_DB", getProgram()->getModule());
	res.load();
	if (!res.isLoaded()) {
		//throw ex
		return;
	}
	db.exec(res.getData());
}

