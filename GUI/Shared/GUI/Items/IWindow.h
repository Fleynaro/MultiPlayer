#pragma once

#include "Items.h"

namespace GUI::Window
{
#ifdef GUI_IS_MULTIPLAYER
	using namespace Generic;
#endif

	class IWindow :
		public Item,
		public Attribute::Name<IWindow>,
		public Events::OnClose<IWindow>
	{
	public:
		IWindow(std::string name, Container* container = new Container)
			: Attribute::Name<IWindow>(name), m_container(container)
		{}
		~IWindow() {
			delete m_container;
			for (auto it : m_childs) {
				delete it;
			}
		}

		Container& getMainContainer() {
			return *m_container;
		}

		void render() override {
			pushParams();
			if (ImGui::Begin(getName().c_str(), &m_open, m_flags))
			{
				calculateActualInfo();
				onRender();
				checkIfFocused();
				getMainContainer().show();
				ImGui::End();
			}
			renderChildWindows();

			checkToClose();
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
		virtual void onRender() {}

		void renderChildWindows() {
			for (auto it : m_childs) {
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
			return m_flags & flags != 0;
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
			window->setCloseEvent(
				new Events::EventUI(
					EVENT_LAMBDA(info) {				
						auto win = (IWindow*)info->getSender();
						removeWindow(win);
						delete win;
					}
				)
			);
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
			delete this;
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