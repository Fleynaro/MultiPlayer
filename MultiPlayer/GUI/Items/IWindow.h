#pragma once

#include "Items.h"

namespace GUI::Window
{
	using namespace Generic;

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
				onRender();
				checkIfFocused();
				getMainContainer().show();
				ImGui::End();
			}
			renderChildWindows();

			checkToClose();
		}
	protected:
		virtual void onRender() {}

		void renderChildWindows() {
			for (auto it : m_childs) {
				it->show();
			}
		}

		virtual void pushParams() {
			if (m_x != -1.f) {
				ImGui::SetNextWindowPos(ImVec2(m_x, m_y));
			}
			if (m_width != -1.f) {
				ImGui::SetNextWindowSize(ImVec2(m_width, m_height));
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
			return ImGui::GetWindowSize().x;
		}

		float getY() {
			return ImGui::GetWindowSize().y;
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
	protected:
		bool m_open = true;
		bool m_focused = false;
		Container* m_container;
		ImGuiWindowFlags m_flags = ImGuiWindowFlags_None;
		std::list<IWindow*> m_childs;

		float m_width = -1.f;
		float m_height = -1.f;
		float m_x = -1.f;
		float m_y = -1.f;
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
};