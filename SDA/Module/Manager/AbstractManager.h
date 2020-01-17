#pragma once
#include "SDA.h"

namespace CE
{
	class AbstractManager
	{
	public:
		AbstractManager(ProgramModule* programModule)
			: m_programModule(programModule)
		{}
		
		ProgramModule* getProgramModule() {
			return m_programModule;
		}
	private:
		ProgramModule* m_programModule;
	};

	namespace API
	{
		class IItemDB
		{
		public:
			virtual void lock() = 0;
			virtual void unlock() = 0;
			virtual void save() = 0;
		};

		class ItemDB : public IItemDB
		{
		public:
			void lock() override {
				if (m_locked)
					return;
				m_mutex.lock();
				m_locked = true;
			}

			void unlock() override {
				m_mutex.unlock();
				m_locked = false;
			}

			void change(std::function<void()> func) {
				lock();
				func();
				unlock();
			}

			void changeAndSave(std::function<void()> func) {
				lock();
				func();
				save();
				unlock();
			}
		private:
			std::mutex m_mutex;
			bool m_locked = false;
		};
	};
};