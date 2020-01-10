#pragma once

#include "Game/GameAppInfo.h"
#include "SDK/World/Ped/Ped.h"
#include "Template/CategoryListSearchWithPageNav.h"
#include "ILoadContent.h"
#include "TypeView.h"

namespace GUI::Widget
{
	class GameAnimListSearch
		: public Template::CategoryListSearchWithPageNav, public ILoadContentThreaded
	{
		LoadedContent<json>* m_animList;
		bool m_animListReleased = false;
	public:
		GameAnimListSearch()
		{
			m_clickTextToCopy = new Events::EventUI(
				EVENT_METHOD_PASS(clickTextToCopy)
			);
			m_clickTextToCopy->setCanBeRemoved(false);

			getMainContainer().text("Loading...");

			m_animList = new LoadedContent<json>;
			m_animList->load(&loadAnimList);
			getPageNav()->setItemCountOnPage(300);
		}

		~GameAnimListSearch() {
			if (!m_animListReleased)
				m_animList->markAsNoLongerNeeded();
		}

		static void loadAnimList(LoadedContent<json>* animList) {
			JSON_Res res("SDK_ANIMS", GameAppInfo::GetInstancePtr()->getDLL());
			res.load();
			if (!res.isLoaded()) {
				animList->markAsLoaded();
				animList->markAsNoLongerNeeded();
				return;
			}

			animList->setData(
				res.getData()
			);
			animList->markAsLoaded();
		}

		void loadingCheckUpdate() override {
			if (m_animListReleased || !m_animList->isLoadedAndNeeded())
				return;

			getMainContainer().removeLastItem();
			addNextPageNav();
			for (json::iterator dict = m_animList->getData().begin(); dict != m_animList->getData().end(); ++dict)
			{
				auto& category = beginCategory(dict.key());
				buildCategory(category, dict.key(), dict.value());
			}
			addNextPageNav();
			showAll();

			m_animList->markAsNoLongerNeeded();
			m_animListReleased = true;
		}


		class AnimItem : public Item
		{
		public:
			AnimItem(const std::string& dictName, const std::string& animName)
				: Item(new TreeNode(animName, false)), m_dictName(dictName), m_animName(animName)
			{}

			std::string& getDictName() {
				return m_dictName;
			}

			std::string& getAnimName() {
				return m_animName;
			}
		private:
			std::string m_dictName;
			std::string m_animName;
		};


		void buildCategory(Category& cat, const std::string& dictName, json animsInDict)
		{
			for (auto anim : animsInDict) {
				cat.addItem(
					buildAnim(dictName, anim.get<std::string>())
				);
			}
		}

		Item* buildAnim(const std::string& dictName, const std::string& animName)
		{
			auto item = (new AnimItem(dictName, animName));
			auto container = item->getContainer<TreeNode>();

			(*container)
				.separator()
				.text("Dictionary: ").sameLine(0.f)
				.addItem(
					new TypeView::TextToCopy(
						dictName,
						ColorRGBA(0xC5F5D5AA),
						m_clickTextToCopy
					)
				)
				.text("Animation: ").sameLine(0.f)
				.addItem(
					new TypeView::TextToCopy(
						animName,
						ColorRGBA(0x73EC99AA),
						m_clickTextToCopy
					)
				)
				.newLine()
				.addItem(
					new GUI::Elements::Button::ButtonStd(
						"Play",
						new Events::EventSDK(
							EVENT_LAMBDA(info) {
								auto sender = (AnimItem*)((GUI::Elements::Button::ButtonStd*)info->getSender())->getParent();
								
								SDK::Ped(SDK::Ped::GetLocalPlayerPed()).playAnim(
									SDK::ANIM::NEW(
										sender->getDictName(),
										sender->getAnimName()
									)
									.setConfig(SDK::ANIM::CFG_Standart)
								);
							}
						)
					)
				);

			item->setKeywordList({ dictName, animName });
			return item;
		}

		Events::EventUI* m_clickTextToCopy = nullptr;
		EVENT_METHOD(clickTextToCopy, info)
		{
			auto sender = (TypeView::TextToCopy*)info->getSender();
			ImGui::SetClipboardText(sender->getText().c_str());
		}
	};
};