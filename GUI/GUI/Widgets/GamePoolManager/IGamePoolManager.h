#pragma once

#include "SDK/Pool.h"
#include "../Template/CategoryListSearchWithPageNav.h"
#include "../TypeView.h"

namespace GUI::Widget
{
	class IGamePoolManager
		: public Template::CategoryListSearchWithPageNav
	{
	public:
		IGamePoolManager() {
			m_clickTextToCopy = new Events::EventUI(
				EVENT_METHOD_PASS(clickTextToCopy)
			);
			m_clickTextToCopy->setCanBeRemoved(false);

			m_showItemCount = false;
			getPageNav()->setItemCountOnPage(50);
		}
		~IGamePoolManager() {
			delete m_clickTextToCopy;
		}

		Events::EventUI* m_clickTextToCopy = nullptr;
		EVENT_METHOD(clickTextToCopy, info)
		{
			auto sender = (TypeView::TextToCopy*)info->getSender();
			ImGui::SetClipboardText(sender->getText().c_str());
		}

		virtual void updateList() = 0;
	};
};