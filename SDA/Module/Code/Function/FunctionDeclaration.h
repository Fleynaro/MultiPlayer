#pragma once
#include <DB/DomainObject.h>
#include <DB/AbstractMapper.h>
#include "FunctionSignature.h"

namespace CE
{
	class FunctionDeclManager;

	namespace Function
	{
		using ArgNameList = std::vector<std::string>;
		class FunctionDefinition;

		class FunctionDecl : public DB::DomainObject
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

			Desc& getDesc();

			virtual std::string getSigName();

			virtual std::string getName();

			Signature& getSignature();

			ArgNameList& getArgNameList();

			virtual Role getRole();

			bool isFunction();

			void addArgument(Type::Type* type, const std::string& name);

			void changeArgument(int id, Type::Type* type, const std::string& name = "");

			void removeLastArgument();

			void deleteAllArguments();

			std::list<FunctionDefinition*>& getFunctions() {
				return m_functions;
			}

			FunctionDeclManager* getManager();

			static bool isFunction(Role role);
		private:
			Desc m_desc;
			Signature m_signature;
			ArgNameList m_argNames;
			FunctionDeclManager* m_manager;
			std::list<FunctionDefinition*> m_functions;
		};
	};
};