#pragma once
#include "Signature.h"
#include <DB/DomainObject.h>
#include <DB/AbstractMapper.h>

namespace CE
{
	namespace Function
	{
		using ArgNameList = std::vector<std::string>;

		class FunctionDecl : public DB::DomainObject, public Desc
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

			FunctionDecl(const std::string& name, const std::string& desc = "");

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
		private:
			Signature m_signature;
			ArgNameList m_argNames;

		};
	};
};