#pragma once

#include "Items.h"

namespace GUI::Window
{
#ifdef GUI_IS_MULTIPLAYER
	using namespace Generic;
#endif

	class IWindow :
		public Item,
		public Events::OnClose<IWindow>,
		public Attribute::Id<IWindow>,
		public Attribute::Name<IWindow>
	{
	public:
		IWindow(std::string name, Container* container = new Container)
			: Attribute::Name<IWindow>(name), Events::OnClose<IWindow>(this, this)
		{
			setMainContainer(container);
		}

		~IWindow() {
			m_container->destroy();
			for (auto it : m_childs) {
				it->destroy();
			}
		}

		Container& getMainContainer() {
			return *m_container;
		}

		Container* getMainContainerPtr() {
			return m_container;
		}

		void setMainContainer(Container* container) {
			m_container = container;
			container->setParent(this);
		}

		void render() override {
			pushParams();

			pushIdParam();
			bool isOpen = ImGui::Begin(getName().c_str(), &m_open, m_flags);
			popIdParam();

			if (isOpen)
			{
				calculateActualInfo();
				onRender();
				checkIfFocused();
				getMainContainer().show();
				ImGui::End();
			}
			renderChildWindows();

			checkToClose();
			handleEventMessages();
		}

	private:
		void calculateActualInfo() {
			auto posVec = ImGui::GetWindowPos();
			m_actualX = posVec.x;
			m_actualY = posVec.y;

			auto sizeVec = ImGui::GetWindowSize();
			m_actualWidth = sizeVec.x;
			m_actualHeight = sizeVec.y;
		}
	protected:
		IWindow* getWindow() override {
			return this;
		}

		virtual void onRender() {}

		void renderChildWindows() {
			for (auto it : m_childs) {
				if (m_childs.size() == 0)
					throw Exception("some error");
				it->show();
			}
		}

		virtual void pushParams() {
			if (m_x != -1.f && isFlags(ImGuiWindowFlags_NoMove)) {
				ImGui::SetNextWindowPos(ImVec2(m_x, m_y));
			}

			float width = m_width;
			float height = m_height;
			if (width != 0 || height != 0) {
				if (!isFlags(ImGuiWindowFlags_NoResize)) {
					if (width != 0) {
						if (width > m_actualWidth) {
							m_actualWidth = width;
						}
						width = m_actualWidth;
					}
					if (height != 0) {
						if (height > m_actualHeight) {
							m_actualHeight = height;
						}
						height = m_actualHeight;
					}
				}
				ImGui::SetNextWindowSize(ImVec2(width, height));
			}
		}

		void checkToClose() {
			if (m_open == false) {
				sendCloseEvent();
			}
		}

		void checkIfFocused() {
			m_focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
		}
	public:
		bool isFlags(ImGuiWindowFlags flags) {
			return (m_flags & flags) != 0;
		}

		IWindow& setFlags(ImGuiWindowFlags flags) {
			m_flags |= flags;
			return *this;
		}

		IWindow& removeFlags(ImGuiWindowFlags flags) {
			m_flags &= ~flags;
			return *this;
		}

		IWindow& setOpen(bool state) {
			m_open = state;
			return *this;
		}

		IWindow& setWidth(float value) {
			m_width = value;
			return *this;
		}

		IWindow& setHeight(float value) {
			m_height = value;
			return *this;
		}

		IWindow& setPosX(float value) {
			m_x = value;
			return *this;
		}

		IWindow& setPosY(float value) {
			m_y = value;
			return *this;
		}

		bool isFocused() {
			return m_focused;
		}

		float getX() {
			return m_actualX;
		}

		float getY() {
			return m_actualY;
		}

		IWindow* getParent() {
			return (IWindow*)Item::getParent();
		}

		IWindow& addWindow(IWindow* window) {
			m_childs.push_back(window);
			window->setParent(this);
			window->getCloseEvent() +=
				[&](Events::ISender* sender) {
					auto win = static_cast<IWindow*>(sender);
					win->close();
				};
			return *this;
		}

		IWindow& removeWindow(IWindow* window) {
			m_childs.remove(window);
			return *this;
		}

		void close() {
			if (getParent() != nullptr) {
				getParent()->removeWindow(this);
			}
			destroy();
		}

		void addEventMessage(Events::IEventMessage* message) override {
			m_eventMessages.push_back(message);
		}

		void showWinMessage(const std::string& message) {
			class ModalWin : public IWindow
			{
			public:
				ModalWin(const std::string& message)
					: IWindow("Message"), m_message(message)
				{
					setFlags(ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize);
				}

				void render() override {
					ImGui::OpenPopup(getName().c_str());
					if (ImGui::BeginPopupModal(getName().c_str(), &m_open, m_flags)) {
						ImGui::Text(m_message.c_str());
						ImGui::EndPopup();
					}
					if (!ImGui::IsPopupOpen(getName().c_str())) {
						m_open = false;
						checkToClose();
					}

					handleEventMessages();
				}
			private:
				std::string m_message;
			};

			auto win = new ModalWin(message);
			addWindow(win);
			win->getCloseEvent() +=
				[&](Events::ISender* sender) {
					m_handleEventMessageEnabled = true;
				};
			m_handleEventMessageEnabled = false;
		}
	private:
		std::list<Events::IEventMessage*> m_eventMessages;
		bool m_handleEventMessageEnabled = true;

		void handleEventMessages() override {
			if (!m_handleEventMessageEnabled)
				return;

			using namespace Events;
			bool isContinue = true;
			for (auto& message : m_eventMessages) {
				try {
					if(isContinue)
						message->execute();
				}
				catch (const GUI::Exception& ex) {
					if (ex.getSource() != nullptr) {
						ex.getSource()->onExceptionOccured(ex);
					}

					if (ex.m_winMessageShow) {
						showWinMessage(ex.getMessage());
						//MY TODO*: return; + remove handled messages
					}

					isContinue = false;
				}

				delete message;
			}
			m_eventMessages.clear();
		}
	protected:
		bool m_open = true;
		bool m_focused = false;
		Container* m_container;
		ImGuiWindowFlags m_flags = ImGuiWindowFlags_None;
		std::list<IWindow*> m_childs;

		float m_width = 0.0;
		float m_height = 0.0;
		float m_x = -1.f;
		float m_y = -1.f;

		float m_actualWidth = 0.0;
		float m_actualHeight = 0.0;
		float m_actualX = 0.0;
		float m_actualY = 0.0;
	};


	class IWindowWithMenu : public IWindow
	{
	public:
		IWindowWithMenu(std::string name, Container* menu = new Container, Container* container = new Container)
			: m_menu(menu), IWindow(name, container)
		{}
		~IWindowWithMenu() {
			delete m_menu;
		}

		void render() override {
			pushParams();
			if (ImGui::Begin(getName().c_str(), &m_open, m_flags | ImGuiWindowFlags_MenuBar))
			{
				onRender();
				checkIfFocused();
				if (ImGui::BeginMenuBar()) {
					getMenu().show();
					ImGui::EndMenuBar();
				}
				getMainContainer().show();
				ImGui::End();
			}
			renderChildWindows();

			checkToClose();
		}

		Container& getMenu() {
			return *m_menu;
		}
	protected:
		Container* m_menu;
	};

	class InvisibleWindow : public IWindow
	{
	public:
		InvisibleWindow(std::string name)
			: IWindow("Invisible window: " + name)
		{}

		void render() override {
			pushParams();
			renderChildWindows();
		}
	};
};