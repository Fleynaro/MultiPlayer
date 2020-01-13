#pragma once

#include "../Items/IWidget.h"

namespace GUI::Widget
{
	namespace Elements
	{
		class PopupContextWindow
			: public MenuContainer, public Attribute::Pos<PopupContextWindow>
		{
		public:
			PopupContextWindow(std::string name)
				: MenuContainer(name)
			{
			}

			void render() override {
				if (isOpen()) {
					ImGui::OpenPopup(getName().c_str());
				}
				pushPosParam();
				if (ImGui::BeginPopupContextWindow(getName().c_str(), m_mouseBtn))
				{
					Container::render();
					ImGui::EndPopup();
				}

				if (ImGui::IsMouseClicked(0)) {
					close();
					ImGui::CloseCurrentPopup();
				}
			}
		protected:
			int m_mouseBtn = 1;
		};
	};

	class PopupContextWindow : public IWidget
	{
	public:
		PopupContextWindow(std::string name)
			: IWidget(name, new Elements::PopupContextWindow(name))
		{

		}

		void open() {
			getPopupCtxWin().open();
		}

		void close() {
			if (!isOpen())
				return;
			getPopupCtxWin().close();
			ImGui::CloseCurrentPopup();
			m_curPopupCtxWin = nullptr;
		}

		bool isOpen() {
			return getPopupCtxWin().isOpen();
		}

		Elements::PopupContextWindow& getPopupCtxWin() {
			return *getPopupCtxWinPtr();
		}

		Elements::PopupContextWindow* getPopupCtxWinPtr() {
			return (Elements::PopupContextWindow*)getMainContainerPtr();
		}

		static void Open(PopupContextWindow* ctxWin) {
			if (GetCurrent() != nullptr) {
				GetCurrent()->close();
			}
			ctxWin->open();
			m_curPopupCtxWin = ctxWin;
		}

		static PopupContextWindow* GetCurrent() {
			return m_curPopupCtxWin;
		}

		static void Render() {
			if (GetCurrent() != nullptr) {
				GetCurrent()->getMainContainer().show();
			}
		}
	private:
		inline static PopupContextWindow* m_curPopupCtxWin = nullptr;
	};
};