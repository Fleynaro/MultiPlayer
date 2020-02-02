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
		class ArgName
			: public Elements::Text::Text,
			public Events::ISender,
			public Events::OnLeftMouseClick<ArgName>,
			public Events::OnRightMouseClick<ArgName>
		{
		public:
			ArgName(const std::string& name, Events::Event* event)
				: Elements::Text::Text(name), Events::OnLeftMouseClick<ArgName>(event)
			{}

			void render() {
				Elements::Text::Text::render();
				sendLeftMouseClickEvent();
			}
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
		}

		int m_argumentSelectedIdx = 0;
	protected:
		void buildReturnValueType()
		{
			(*this)
				.addItem(new Type(getFunction()->getSignature().getReturnType()));
		}

		void buildName()
		{
			(*this)
				.text(" " + getFunction()->getDeclaration().Desc::getName())
				.beginImGui([&] {
					m_leftMouseClickOnFuncName.sendLeftMouseClickEvent();
				})
				.sameLine(0.f);
		}

		void buildArgumentList()
		{
			(*this)
				.sameLine(0.f)
				.text("(")
				.sameLine(0.f);

			int idx = 0;
			for (auto& type : getFunction()->getSignature().getArgList()) {
				buildArgument(idx, getFunction()->getArgNameList()[idx], type,
					getFunction()->getSignature().getArgList().size() == idx + 1);
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
				.addItem(new Type(type))
				.addItem(new ArgName(argName, m_leftMouseClickOnArgName))
				.sameLine(0.f);
		}

		ColorRGBA getColor() {
			return -1;
		}

		API::Function::Function* m_function;
	private:
		Events::OnLeftMouseClick<Signature> m_leftMouseClickOnType;
		Events::OnLeftMouseClick<Signature> m_leftMouseClickOnFuncName;
		Events::Event* m_leftMouseClickOnArgName;

		Function::Function* getFunction() {
			return m_function->getFunction();
		}
	};
};