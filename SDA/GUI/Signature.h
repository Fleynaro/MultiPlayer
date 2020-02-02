#pragma once
#include "Type.h"
#include <Manager/FunctionManager.h>

using namespace CE;

namespace GUI::Units
{
	class Signature
		: public Container
	{
	public:
		class Name
			: public Elements::Text::Text,
			public Events::ISender,
			public Events::OnLeftMouseClick<Name>
		{
		public:
			Name(const std::string& name, Events::Event* clickEvent)
				: Elements::Text::Text(name), Events::OnLeftMouseClick<Name>(clickEvent)
			{}

			void render() {
				Elements::Text::Text::render();
				sendLeftMouseClickEvent();
			}
		};

		class ArgName : public Name
		{
		public:
			ArgName(int id, const std::string& name, Events::Event* clickEvent)
				: m_id(id), Name(name, clickEvent)
			{}

			int getArgumentId() {
				return m_id;
			}
		private:
			int m_id;
		};

		class Type : public Units::Type
		{
		public:
			Type(int id, CE::Type::Type* type, Events::Event* eventHandler)
				: m_id(id), Units::Type(type, eventHandler)
			{}

			int getId() {
				return m_id;
			}
		private:
			int m_id;
		};


		Signature(
			API::Function::Function* function,
			Events::Event* leftMouseClickOnType = nullptr,
			Events::Event* leftMouseClickOnFuncName = nullptr,
			Events::Event* leftMouseClickOnArgName = nullptr
		)
			:
			m_function(function),
			m_leftMouseClickOnType(leftMouseClickOnType),
			m_leftMouseClickOnFuncName(leftMouseClickOnFuncName),
			m_leftMouseClickOnArgName(leftMouseClickOnArgName)
		{
			buildReturnValueType();
			buildName();
			buildArgumentList();

			m_leftMouseClickOnType->setCanBeRemoved(false);
			m_leftMouseClickOnFuncName->setCanBeRemoved(false);
			m_leftMouseClickOnArgName->setCanBeRemoved(false);
		}

		~Signature() {
			Events::Event* eventHandlers[] = {
				m_leftMouseClickOnType,
				m_leftMouseClickOnFuncName,
				m_leftMouseClickOnArgName
			};

			for (int i = 0; i < 3; i++) {
				if (eventHandlers[i] != nullptr && eventHandlers[i]->canBeRemovedBy(nullptr)) {
					delete eventHandlers[i];
				}
			}
		}

		int m_argumentSelectedIdx = 0;
	protected:
		void buildReturnValueType()
		{
			(*this)
				.addItem(new Type(0, getFunction()->getSignature().getReturnType(), m_leftMouseClickOnType));
		}

		void buildName()
		{
			std::string funcName = " " + getFunction()->getDeclaration().Desc::getName();
			(*this)
				.addItem(new Name(funcName, m_leftMouseClickOnFuncName))
				.sameLine(0.f);
		}

		void buildArgumentList()
		{
			(*this)
				.sameLine(0.f)
				.text("(")
				.sameLine(0.f);

			int idx = 1;
			for (auto& type : getFunction()->getSignature().getArgList()) {
				buildArgument(idx, getFunction()->getArgNameList()[idx - 1], type,
					getFunction()->getSignature().getArgList().size() == idx);
				idx++;
			}

			(*this)
				.sameLine(0.f)
				.text(")")
				.sameLine(0.f);
		}

		void buildArgument(int idx, const std::string& name, CE::Type::Type* type, bool isFinal = false)
		{
			std::string argName = " " + name + (!isFinal ? ", " : "");
			(*this)
				.sameLine(0.f)
				.addItem(new Type(idx, type, m_leftMouseClickOnType))
				.addItem(new ArgName(idx, argName, m_leftMouseClickOnArgName))
				.sameLine(0.f);
		}

		ColorRGBA getColor() {
			return -1;
		}

		API::Function::Function* m_function;
	private:
		Events::Event* m_leftMouseClickOnType;
		Events::Event* m_leftMouseClickOnFuncName;
		Events::Event* m_leftMouseClickOnArgName;

		Function::Function* getFunction() {
			return m_function->getFunction();
		}
	};
};