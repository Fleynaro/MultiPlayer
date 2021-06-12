#pragma once
#include "GhidraSync.h"

namespace CE::Ghidra
{
	class GhidraObjectLoader
	{
	public:
		GhidraObjectLoader(CE::Project* programModule);

		~GhidraObjectLoader();

		void analyse();

		std::list<IObject*>& getObjectsToUpsert();

		std::list<IObject*>& getObjectsToRemove();
	private:
		CE::Project* m_programModule;
		std::list<IObject*> m_upsertedObjs;
		std::list<IObject*> m_removedObjs;
	};
};