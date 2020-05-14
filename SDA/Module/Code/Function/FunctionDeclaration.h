#pragma once
#include <DB/DomainObject.h>
#include <DB/AbstractMapper.h>
#include "FunctionSignature.h"
#include <Utils/Description.h>

namespace CE
{
	class FunctionDeclManager;

	namespace Function
	{
		using ArgNameList = std::vector<std::string>;
		class FunctionDefinition;

		class FunctionDecl : public DB::DomainObject, public Descrtiption
		{
		public:
			enum class Role
			{
				Function,
				Method,
				StaticMethod,
				VirtualMethod,
				Constructor,
				Destructor,
				VirtualDestructor
			};

			FunctionDecl(FunctionDeclManager* manager, const std::string& name, const std::string& desc = "");

			virtual std::string getSigName();

			Signature& getSignature();

			ArgNameList& getArgNameList();

			virtual Role getRole();

			bool isFunction();

			void addArgument(DataTypePtr type, const std::string& name);

			void changeArgument(int id, DataTypePtr type, const std::string& name = "");

			void removeLastArgument();

			void deleteAllArguments();

			std::list<FunctionDefinition*>& getFunctions() {
				return m_functions;
			}

			void setExported(bool toggle);

			bool isExported();

			FunctionDeclManager* getManager();

			static bool isFunction(Role role);
		private:
			Signature m_signature;
			ArgNameList m_argNames;
			FunctionDeclManager* m_manager;
			std::list<FunctionDefinition*> m_functions;
			bool m_exported = false;
		};
	};
};