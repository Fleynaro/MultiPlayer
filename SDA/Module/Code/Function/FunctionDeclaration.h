#pragma once
#include <DB/DomainObject.h>
#include <DB/AbstractMapper.h>
#include "../Type/FunctionSignature.h"
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

			FunctionDecl(FunctionDeclManager* manager, DataType::Signature* signature, const std::string& name, const std::string& desc = "");

			DataType::Signature* getSignature();

			virtual Role getRole();

			bool isFunction();

			std::list<FunctionDefinition*>& getFunctions();

			void setExported(bool toggle);

			bool isExported();

			FunctionDeclManager* getManager();

			static bool isFunction(Role role);
		private:
			DataType::Signature* m_signature;
			FunctionDeclManager* m_manager;
			std::list<FunctionDefinition*> m_functions;
			bool m_exported = false;
		};
	};
};