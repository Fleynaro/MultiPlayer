#pragma once
#include "AbstractManager.h"
#include <Statistic/Statistic.h>

namespace CE
{
	class StatManager : public IManager
	{
	public:
		StatManager(SDA* sda)
			: IManager(sda)
		{
			m_funcArgManager = new Stat::Function::Args::Manager;
			m_funcRetManager = new Stat::Function::Ret::Manager;
			initGeneralDB();
			initGarbagers(1);
		}

		void initGarbagers(int amount) {
			for (int i = 1; i <= amount; i++)
			{
				{
					auto garbager = new Stat::Function::Args::Garbager(this);
					garbager->initDataBase(
						FS::File(
							getSDA()->getDirectory().next("garbagers"),
							"call_before" + std::to_string(i) + ".db"
						)
					);
					//garbager->clear();
					garbager->start();
					getFuncArgManager()->addGarbager(garbager);
				}

				{
					auto garbager = new Stat::Function::Ret::Garbager(this);
					garbager->initDataBase(
						FS::File(
							getSDA()->getDirectory().next("garbagers"),
							"call_after" + std::to_string(i) + ".db"
						)
					);
					//garbager->clear();
					garbager->start();
					getFuncRetManager()->addGarbager(garbager);
				}
			}
		}

		void initGeneralDB()
		{
			m_general_db = new SQLite::Database(FS::File(getSDA()->getDirectory(), "general_stat.db").getFilename(), SQLite::OPEN_READWRITE);
		}

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