#pragma once
#include <Address/AddressRange.h>
#include <GhidraSync/GhidraObject.h>
#include "../Type/FunctionSignature.h"
#include "../Symbol/Symbol.h"

namespace CE
{
	namespace Trigger::Function
	{
		class Hook;
	};

	class FunctionManager;
	class ProcessModule;

	namespace Function
	{
		class Function : public DB::DomainObject, public Ghidra::Object, public IDescription
		{
		public:
			Function(FunctionManager* manager, Symbol::FunctionSymbol* functionSymbol, ProcessModule* module, AddressRangeList ranges, DataType::Signature* signature);

			Symbol::FunctionSymbol* getFunctionSymbol();

			const std::string getName() override;

			const std::string getComment() override;

			void setName(const std::string& name) override;

			void setComment(const std::string& comment) override;

			DataType::Signature* getSignature();

			void* getAddress();

			AddressRangeList& getAddressRangeList();

			void addRange(AddressRange range);

			bool isContainingAddress(void* addr);

			Symbol::MemoryArea* getStackMemoryArea();

			void setStackMemoryArea(Symbol::MemoryArea* stackMemoryArea);

			Symbol::MemoryArea* getBodyMemoryArea();

			void setBodyMemoryArea(Symbol::MemoryArea* bodyMemoryArea);

			Trigger::Function::Hook* getHook();

			bool hasHook();

			void createHook();

			void setExported(bool toggle);

			bool isExported();

			Ghidra::Id getGhidraId() override;

			ProcessModule* getProcessModule();

			FunctionManager* getManager();
		private:
			Symbol::FunctionSymbol* m_functionSymbol;
			ProcessModule* m_module;
			AddressRangeList m_ranges;
			DataType::Signature* m_signature;
			Symbol::MemoryArea* m_stackMemoryArea = nullptr;
			Symbol::MemoryArea* m_bodyMemoryArea = nullptr;
			Trigger::Function::Hook* m_hook = nullptr;
			FunctionManager* m_manager;
			bool m_exported = false;
		};
	};
};