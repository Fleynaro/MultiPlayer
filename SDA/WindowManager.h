#pragma once
#include "Shared/GUI/Items/IWindow.h"

using namespace GUI::Window;

class WindowManager
{
public:
	WindowManager() {
		m_mainWindow = new InvisibleWindow("WindowManager");
		setVisible(true);
	}

	void addWindow(IWindow* window) {
		m_mainWindow->addWindow(window);
	}

	void removeWindow(IWindow* window) {
		m_mainWindow->removeWindow(window);
	}

	void setVisible(bool state) {
		m_mainWindow->setDisplay(state);
	}

	bool isVisible() {
		return m_mainWindow->isShown();
	}

	void render() {
		m_mainWindow->show();
	}
private:
	GUI::Window::InvisibleWindow* m_mainWindow;
};