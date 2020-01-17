#pragma once
#include "Analyser.h"
#include <Code/Function/Method.h>
#include <DynHook/DynHook.h>
#include <SQLiteCpp/SQLiteCpp.h>
#include <Utility/FileWrapper.h>

using namespace SQLite;

namespace CE
{
	class StatManager;

	namespace Trigger::Function
	{
		class Trigger;
	};

	namespace Stat::Function
	{
			template<typename T>
			class ICollector
			{
			public:
				ICollector(StatManager* statManager = nullptr)
					: m_statManager(statManager)
				{}

				~ICollector() {
					if (m_db != nullptr) {
						delete m_db;
					}
				}

				void start() {
					m_thread = std::thread(&ICollector<T>::handler, this);
					m_thread.detach();
				}

				void initDataBase(SQLite::Database* db)
				{
					if (m_db != nullptr) {
						delete m_db;
					}
					m_db = db;
				}

				virtual void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook) = 0;

				int getSize() {
					return m_buffers.size();
				}

				SQLite::Database& getDB() {
					return *m_db;
				}

				virtual void copyStatTo(SQLite::Database& db) {};
				virtual void clear() {}
			protected:
				virtual void handler() = 0;

				std::queue<T> m_buffers;
				std::mutex m_bufferMutex;
				std::mutex m_dbMutex;
				std::thread m_thread;

				StatManager* m_statManager;
				SQLite::Database* m_db = nullptr;
			};

			template<typename B, typename G = ICollector<B>>
			class AbstractManager
			{
			public:
				inline void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
				{
					selectGarbager1()->add(trigger, hook);
					//m_counter++;
				}

				ICollector<B>* selectGarbager1() {
					ICollector<B>* result = nullptr;
					int size = INT_MAX;
					for (ICollector<B>* garbager : m_garbagers) {
						if (garbager->getSize() < size) {
							result = garbager;
							size = garbager->getSize();
						}
					}
					return result;
				}

				ICollector<B>* selectGarbager2() {
					return m_garbagers[m_counter % m_garbagers.size()];
				}

				void copyStatTo(SQLite::Database& db)
				{
					for (auto it : m_garbagers) {
						it->copyStatTo(db);
						it->clear();
					}
				}

				void addCollector(ICollector<B>* garbager)
				{
					m_garbagers.push_back(garbager);
				}
			protected:
				std::vector<ICollector<B>*> m_garbagers;
				std::atomic<uint64_t> m_counter = 0;
			};

			namespace Args
			{
				class Buffer
				{
				public:
					uint64_t m_uid = 0;
					uint64_t m_args[12] = { 0 };
					uint64_t m_xmm_args[4] = { 0 };
					CE::Hook::DynHook* m_hook = nullptr;
					CE::Trigger::Function::Trigger* m_trigger = nullptr;

					Buffer(CE::Hook::DynHook* hook, CE::Trigger::Function::Trigger* trigger)
					{
						m_uid = hook->getUID();
						for (int i = 1; i <= hook->getArgCount(); i++) {
							m_args[i - 1] = hook->getArgumentValue(i);
						}
						if (hook->isXmmSaved()) {
							for (int i = 1; i <= min(4, hook->getArgCount()); i++) {
								m_xmm_args[i - 1] = hook->getXmmArgumentValue(i);
							}
						}
						m_hook = hook;
						m_trigger = trigger;
					}

					inline CE::Function::Function* getFunction() {
						return (CE::Function::Function*)m_hook->getUserPtr();
					}
				};

				class Collector : public ICollector<Buffer>
				{
				public:
					Collector(StatManager* statManager)
						: ICollector<Buffer>(statManager)
					{}

					void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook) override;

					void handler() override {
						while (true)
						{
							m_bufferMutex.lock();
							if (m_buffers.empty()) {
								m_bufferMutex.unlock();
								Sleep(50);
								continue;
							}

							m_dbMutex.lock();
							SQLite::Transaction transaction(getDB());

							for (int i = 0; i < m_buffers.size(); i++) {
								send(m_buffers.front());
								m_buffers.pop();

								static std::atomic<uint64_t> g_counter = 0;
								g_counter++;
								int c = g_counter;
								if (c % 10000 == 0) {
									printf("\n%i) Args", c);
								}
							}
							m_bufferMutex.unlock();


							transaction.commit();
							m_dbMutex.unlock();
							Sleep(30);
						}
					}

					void copyStatTo(SQLite::Database& db)
					{
						m_dbMutex.lock();
						{
							SQLite::Statement query(db, "ATTACH DATABASE ?1 AS call_before");
							query.bind(1, getDB().getFilename());
							query.exec();
						}

						{
							SQLite::Statement query(db, "INSERT INTO sda_call_before SELECT * FROM call_before.sda_call_before");
							query.exec();
						}

						{
							SQLite::Statement query(db, "INSERT INTO sda_call_args SELECT * FROM call_before.sda_call_args");
							query.exec();
						}

						{
							SQLite::Statement query(db, "DETACH DATABASE call_before");
							query.exec();
						}
						m_dbMutex.unlock();
					}

					void clear() override
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
							SQLite::Statement query(getDB(), "VACUUM");
							query.exec();
						}
					}

					void send(Buffer& buffer);
				};

				class Manager : public AbstractManager<Buffer, Collector> {};
			};

			namespace Ret
			{
				class Buffer
				{
				public:
					uint64_t m_uid = 0;
					uint64_t m_ret = 0;
					uint64_t m_xmm_ret = 0;
					CE::Hook::DynHook* m_hook = nullptr;
					CE::Trigger::Function::Trigger* m_trigger = nullptr;

					Buffer(CE::Hook::DynHook* hook, CE::Trigger::Function::Trigger* trigger)
					{
						m_uid = hook->getUID();
						m_ret = hook->getReturnValue();
						m_xmm_ret = hook->getXmmReturnValue();
						m_hook = hook;
						m_trigger = trigger;
					}

					inline CE::Function::Function* getFunction() {
						return (CE::Function::Function*)m_hook->getUserPtr();
					}
				};

				class Collector : public ICollector<Buffer>
				{
				public:
					Collector(StatManager* statManager)
						: ICollector<Buffer>(statManager)
					{}

					void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook) override;

					void handler() override {
						while (true)
						{
							m_bufferMutex.lock();
							if (m_buffers.empty()) {
								m_bufferMutex.unlock();
								Sleep(50);
								continue;
							}
							m_dbMutex.lock();
							SQLite::Transaction transaction(getDB());

							for (int i = 0; i < m_buffers.size(); i++) {
								send(m_buffers.front());
								m_buffers.pop();

								static std::atomic<uint64_t> g_counter = 0;
								g_counter++;
								int c = g_counter;
								if (c % 10000 == 0) {
									printf("\n%i) Ret", c);
								}
							}
							m_bufferMutex.unlock();

							transaction.commit();
							m_dbMutex.unlock();
							Sleep(30);
						}
					}

					void copyStatTo(SQLite::Database& db)
					{
						m_dbMutex.lock();
						{
							SQLite::Statement query(db, "ATTACH DATABASE ?1 AS call_after");
							query.bind(1, getDB().getFilename());
							query.exec();
						}

						{
							SQLite::Statement query(db, "INSERT INTO sda_call_after SELECT * FROM call_after.sda_call_after");
							query.exec();
						}

						{
							SQLite::Statement query(db, "DETACH DATABASE call_after");
							query.exec();
						}
						m_dbMutex.unlock();
					}

					void clear() override
					{
						{
							SQLite::Statement query(getDB(), "DELETE FROM sda_call_after");
							query.exec();
						}
						{
							SQLite::Statement query(getDB(), "VACUUM");
							query.exec();
						}
					}

					void send(Buffer& buffer);
				};

				class Manager : public AbstractManager<Buffer, Collector> {};
			};

			class StatInfo
			{
			public:
				StatInfo()
				{}

				struct Value
				{
					CE::Type::SystemType::Set m_set = CE::Type::SystemType::Undefined;
					CE::Type::SystemType::Types m_typeId = CE::Type::SystemType::Void;
					Analyser::Histogram* m_histogram = nullptr;

					Value() = default;

					Value(CE::Type::SystemType::Set set, CE::Type::SystemType::Types typeId, Analyser::Histogram* histogram)
						: m_set(set), m_typeId(typeId), m_histogram(histogram)
					{}
				};

				void addArgument(Value value) {
					m_args.push_back(value);
				}

				void setReturnValue(const Value& value) {
					m_ret = value;
				}

				Value& getArgument(int index) {
					return m_args[index];
				}

				Value& getReturnValue() {
					return m_ret;
				}

				void debugShow()
				{
					printf("\nStatistic of the function\n\nReturn value: ");
					getReturnValue().m_histogram->debugShow();
					for (int i = 0; i < m_args.size(); i++) {
						printf("\nArgument %i: ", i + 1);
						if (getArgument(i).m_set != CE::Type::SystemType::Undefined)
							getArgument(i).m_histogram->debugShow();
					}
				}
			private:
				std::vector<Value> m_args;
				Value m_ret;
			};

			class Account
			{
			public:
				Account(SQLite::Database* db, CE::Function::Function* function)
					: m_db(db), m_function(function)
				{}

				struct CallInfo
				{
					uint64_t m_uid;
					uint64_t m_args[12];
					uint64_t m_xmm_args[4];
					uint64_t m_ret;
					uint64_t m_xmm_ret;
				};

				void iterateCalls(std::function<void(CallInfo& info)> handler, CE::Trigger::Function::Trigger* trigger, int page, int pageSize = 30);

				static StatInfo::Value getValueByAnalysers(Analyser& analyser, Analyser& analyser_xmm, CE::Type::Type* type)
				{
					using namespace CE::Type;
					Analyser& result = analyser;
					if (!analyser.isUndefined() && !analyser_xmm.isUndefined()) {
						if (SystemType::GetNumberSetOf(type) == SystemType::Real) {
							analyser = analyser_xmm;
						}
					}
					else if (!analyser_xmm.isUndefined()) {
						analyser = analyser_xmm;
					}
					return StatInfo::Value(result.getSet(), result.getTypeId(), result.createHistogram());
				}

				StatInfo* createStatInfo(CE::Trigger::Function::Trigger* trigger = nullptr);


				SQLite::Database& getDB() {
					return *m_db;
				}
			private:
				CE::Function::Function* m_function;
				SQLite::Database* m_db;
			};
	};
};