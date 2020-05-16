#pragma once
#include "GhidraSync.h"

namespace CE::Ghidra
{
	class GhidraObjectLoader
	{
	public:
		GhidraObjectLoader(CE::ProgramModule* programModule);

		~GhidraObjectLoader();

		void analyse();

		std::list<IObject*>& getObjectsToUpsert();

		std::list<IObject*>& getObjectsToRemove();
	private:
		CE::ProgramModule* m_programModule;
		std::list<IObject*> m_upsertedObjs;
		std::list<IObject*> m_removedObjs;
	};
};