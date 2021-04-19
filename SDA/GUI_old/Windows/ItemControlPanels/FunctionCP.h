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
			m_signature = new Units::FunctionSignature(m_function);
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