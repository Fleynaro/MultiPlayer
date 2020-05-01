#pragma once
#include "Signature.h"
#include <DB/DomainObject.h>
#include <DB/AbstractMapper.h>
#include <Manager/FunctionDeclManager.h>

namespace CE
{
	namespace Function
	{
		using ArgNameList = std::vector<std::string>;

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

			Signature& getSignature();

			ArgNameList& getArgNameList();

			virtual Role getRole();

			bool isFunction();

			void addArgument(Type::Type* type, const std::string& name);

			void changeArgument(int id, Type::Type* type, const std::string& name = "");

			void removeLastArgument();

			void deleteAllArguments();

			static bool isFunction(Role role);

			FunctionDeclManager* getManager();
		private:
			Desc m_desc;
			Signature m_signature;
			ArgNameList m_argNames;
			FunctionDeclManager* m_manager;
		};
	};
};