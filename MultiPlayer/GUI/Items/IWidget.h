#pragma once

#include "Items.h"

namespace GUI::Widget
{
	using namespace Generic;

	class IWidget
		: public Attribute::Name<IWidget>
	{
	public:
		IWidget(std::string name, Container* container = new Container)
			: Attribute::Name<IWidget>(name), m_container(container)
		{
			getMainContainer()
				.setCanBeRemoved(false);
		}
		~IWidget() {
			delete m_container;
		}

		Container& getMainContainer() {
			return *m_container;
		}

		Container* getMainContainerPtr() {
			return m_container;
		}
	protected:
		Container* m_container;
	};
};