#pragma once
#include "AbstractManager.h"
#include <Statistic/Statistic.h>

namespace CE
{
	class StatManager : public AbstractManager
	{
	public:
		StatManager(ProgramModule* sda)
			: AbstractManager(sda)
		{
			m_funcArgManager = new Stat::Function::Args::Manager;
			m_funcRetManager = new Stat::Function::Ret::Manager;
			initGeneralDB();
			initCollectors(1);
		}

		void initCollectors(int amount) {
			auto collectorDir = getProgramModule()->getDirectory().next("collectors");
			collectorDir.createIfNotExists();

			for (int i = 1; i <= amount; i++)
			{
				{
					auto collector = new Stat::Function::Args::Collector(this);
					collector->initDataBase(openOrCreate_callBeforeDb(
						FS::File(
							collectorDir,
							"call_before" + std::to_string(i) + ".db"
						)
					));
					//collector->clear();
					collector->start();
					getFuncArgManager()->addCollector(collector);
				}

				{
					auto collector = new Stat::Function::Ret::Collector(this);
					collector->initDataBase(openOrCreate_callAfterDb(
						FS::File(
							collectorDir,
							"call_after" + std::to_string(i) + ".db"
						)
					));
					//collector->clear();
					collector->start();
					getFuncRetManager()->addCollector(collector);
				}
			}
		}

		SQLite::Database* openOrCreate_callBeforeDb(FS::File file);
		SQLite::Database* openOrCreate_callAfterDb(FS::File file);
		void initGeneralDB();

		void updateGeneralDB()
		{
			getFuncArgManager()->copyStatTo(getDB());
			getFuncRetManager()->copyStatTo(getDB());
		}

		void clearGeneralDB()
		{
			{
				SQLite::Statement query(getDB(), "DELETE FROM sda_call_before");
				query.exec();
			}
			{
				SQLite::Statement query(getDB(), "DELETE FROM sda_call_args");
				query.exec();
			}
			{
				SQLite::Statement query(getDB(), "DELETE FROM sda_call_after");
				query.exec();
			}
			{
				SQLite::Statement query(getDB(), "VACUUM");
				query.exec();
			}
		}
	public:
		inline Stat::Function::Args::Manager* getFuncArgManager() {
			return m_funcArgManager;
		}

		inline Stat::Function::Ret::Manager* getFuncRetManager() {
			return m_funcRetManager;
		}

		SQLite::Database& getDB() {
			return *m_general_db;
		}
	private:
		SQLite::Database* m_general_db = nullptr;
		Stat::Function::Args::Manager* m_funcArgManager;
		Stat::Function::Ret::Manager* m_funcRetManager;
	};
};