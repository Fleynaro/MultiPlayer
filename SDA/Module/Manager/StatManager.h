#pragma once
#include "AbstractManager.h"
#include <Statistic/Function/Collector/FunctionStatCollector.h>

namespace CE
{
	class StatManager : public AbstractManager
	{
	public:
		StatManager(ProgramModule* sda);

		~StatManager();

		Stat::Function::Collector* getCollector();
	private:
		Stat::Function::Collector* m_collector;
	};
};