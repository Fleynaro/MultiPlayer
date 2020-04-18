#pragma once
#include "FunctionDefinition.h"

namespace CE
{
	namespace Function
	{
		class Function : public IGhidraUnit
		{
		public:
			Function(FunctionDecl* decl, FunctionDefinition* def = nullptr)
				: m_decl(decl), m_def(def)
			{}

			Function(FunctionDefinition* def)
				: m_def(def), m_decl(def->getDeclarationPtr())
			{}

			FunctionDecl& getDeclaration() {
				return *m_decl;
			}

			FunctionDefinition& getDefinition() {
				return *m_def;
			}

			bool hasDefinition() {
				return m_def != nullptr;
			}

			int getId() {
				if (!hasDefinition())
					0;
				return getDefinition().getId();
			}

			void* getAddress() {
				if (!hasDefinition())
					nullptr;
				return getDefinition().getAddress();
			}

			Signature& getSignature() {
				return getDeclaration().getSignature();
			}

			ArgNameList& getArgNameList() {
				return getDeclaration().getArgNameList();
			}

			std::string getName() {
				return getDeclaration().getName();
			}

			std::string getDesc() {
				return getDeclaration().getDesc();
			}

			std::string getSigName() {
				return getDeclaration().getSigName();
			}

			bool isFunction() {
				return getDeclaration().isFunction();
			}

			bool isGhidraUnit() override {
				return m_ghidraUnit;
			}

			void setGhidraUnit(bool toggle) override {
				m_ghidraUnit = toggle;
			}
		protected:
			FunctionDecl* m_decl;
			FunctionDefinition* m_def;
			bool m_ghidraUnit = true;
		};
	};
};