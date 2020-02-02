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
								
				}),
				new Events::EventUI(EVENT_LAMBDA(info) {

				}),
				new Events::EventUI(EVENT_LAMBDA(info) {
					auto argName = static_cast<Units::Signature::ArgName*>(info->getSender());
					//argName->setEvent();
					auto name = argName->getText();
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