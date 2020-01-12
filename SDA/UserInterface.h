#pragma once
#include "GUI/Items/Items.h"
#include "GUI/Items/StyleThemes.h"
#include "GUI/Items/IWindow.h"
#include "GUI/Items/IWidget.h"

using namespace GUI::Window;

class WindowManager
{
public:
	WindowManager()
	{}

	void addWindow(GUI::Window::IWindow* window) {
		window->setCloseEvent(
			new GUI::Events::EventUI(EVENT_LAMBDA(info) {
				auto win = (GUI::Window::IWindow*)info->getSender();
				removeWindow(win);
				delete win;
			})
		);
		m_windows.push_back(window);
	}

	void removeWindow(GUI::Window::IWindow* window) {
		m_windows.remove(window);
		if (m_windows.size() == 0) {
			setVisibleForAll(false);
		}
	}

	void setVisibleForAll(bool state) {
		m_shown = state;
	}

	bool isVisible() {
		return m_shown;
	}

	void render() {
		if (!m_shown)
			return;
		for (auto it : m_windows) {
			it->show();
		}
	}
private:
	std::list<GUI::Window::IWindow*> m_windows;
	bool m_shown = true;
};

class UserInterface
{
public:
	UserInterface()
	{
		m_windowManager = new WindowManager;
	}

	void render() {
		getWindowManager()->render();
	}

	WindowManager* getWindowManager() {
		return m_windowManager;
	}
private:
	WindowManager* m_windowManager;
};