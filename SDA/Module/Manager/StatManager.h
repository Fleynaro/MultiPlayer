#pragma once
#include "AbstractManager.h"
#include <Statistic/Function/FunctionStatCollector.h>

namespace CE
{
	class StatManager : public AbstractManager
	{
	public:
		StatManager(ProgramModule* sda)
			: AbstractManager(sda)
		{
			auto bufferDir = getProgramModule()->getDirectory().next("buffers");
			bufferDir.createIfNotExists();

			m_collector = new Stat::Function::Collector(bufferDir);
		}

		~StatManager() {
			delete m_collector;
		}

		inline Stat::Function::Collector* getCollector() {
			return m_collector;
		}
	private:
		Stat::Function::Collector* m_collector;
	};
};