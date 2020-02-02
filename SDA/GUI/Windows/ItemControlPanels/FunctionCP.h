#pragma once
#include "Shared/GUI/Widgets/Template/ControlPanel.h"
#include "GUI/Signature.h"
#include <Manager/FunctionManager.h>
#include <FunctionTag/FunctionTag.h>

using namespace CE;

namespace GUI::Widget
{
	class FunctionCP : public Template::ControlPanel
	{
	public:
		Container* m_generic;
		Container* m_callFunction;

		FunctionCP(API::Function::Function* function)
			: m_function(function), ControlPanel()
		{
			getSideBar()->addMenuItem("Generic", m_generic = new Container);
			getSideBar()->addMenuItem("Call", m_callFunction = new Container);
			getSideBar()->setSelectedContainer(m_generic);

			buildGeneric();
			buildCallFunction();
		}

		~FunctionCP() {
			delete m_signature;
		}

		void buildSiganture()
		{
			m_signature = new Units::Signature(m_function,
				new Events::EventUI(EVENT_LAMBDA(info) {
					auto type = static_cast<Units::Signature::Type*>(info->getSender());
					auto name = type->getName();
					int id = type->getId();
					int a = 5;
				}),
				new Events::EventUI(EVENT_LAMBDA(info) {
					auto funcName = static_cast<Units::Signature::Name*>(info->getSender());
					auto name = funcName->getText();
					int a = 5;
				}),
				new Events::EventUI(EVENT_LAMBDA(info) {
					auto argName = static_cast<Units::Signature::ArgName*>(info->getSender());
					auto name = argName->getText();
					int a = 6;
				})
			);
			m_signature->setCanBeRemoved(false);
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
		Units::Signature* m_signature;
	};
};