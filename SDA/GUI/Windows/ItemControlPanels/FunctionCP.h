#pragma once
#include "Shared/GUI/Widgets/Template/ControlPanel.h"
#include "GUI/Signature.h"
#include <Manager/FunctionManager.h>
#include <FunctionTag/FunctionTag.h>

using namespace CE;

namespace GUI::Widget
{
	class FunctionList;
};

namespace GUI::Widget
{
	class FunctionCP : public Template::ControlPanel
	{
	public:
		Container* m_generic;
		Container* m_callFunction;
		GUI::Widget::FunctionList* m_callStackViewer;

		FunctionCP(API::Function::Function* function)
			: m_function(function)
		{}

		~FunctionCP() {
			if(m_signature != nullptr)
				delete m_signature;
		}

		void onVisibleOn() override;

		void buildSiganture()
		{
			m_signature = new Units::FunctionSignature(m_function,
				new Events::EventUI(EVENT_LAMBDA(info) {
					auto type = static_cast<Units::FunctionSignature::Type*>(info->getSender());
					auto name = type->getName();
					int id = type->getId();
					int a = 5;
				}),
				new Events::EventUI(EVENT_LAMBDA(info) {
					auto funcName = static_cast<Units::FunctionSignature::Name*>(info->getSender());
					auto name = funcName->getText();
					int a = 5;
				}),
				new Events::EventUI(EVENT_LAMBDA(info) {
					auto argName = static_cast<Units::FunctionSignature::ArgName*>(info->getSender());
					auto name = argName->getText();
					int a = 6;
				})
			);
			m_signature->setParent(this);
		}

		void buildGeneric()
		{
			buildSiganture();
			(*m_generic)
				.addItem(m_signature);
		}

		void buildCallFunction()
		{
			(*m_callFunction)
				.text("callFunction");
		}
	private:
		API::Function::Function* m_function;
		Units::FunctionSignature* m_signature;
	};
};