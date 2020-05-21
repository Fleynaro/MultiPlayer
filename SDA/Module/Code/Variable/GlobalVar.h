#pragma once
#include "../Type/TypeUnit.h"
#include <GhidraSync/GhidraObject.h>

namespace CE
{
	class GlobalVarManager;
	class ProcessModule;

	namespace Variable
	{
		class GlobalVar : public DB::DomainObject, public Ghidra::Object, public Descrtiption
		{
		public:
			GlobalVar(GlobalVarManager* manager, ProcessModule* module, void* addr, const std::string& name, const std::string& comment = "");

			Ghidra::Id getGhidraId();

			ProcessModule* getProcessModule();

			void* getAddress();

			DataTypePtr getType();

			void setType(DataTypePtr type);

			GlobalVarManager* getManager();
		private:
			ProcessModule* m_module;
			void* m_addr;
			DataTypePtr m_type;
			GlobalVarManager* m_manager;
		};
	};
};