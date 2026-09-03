#pragma once
#include <ProjectManager.h>
//#include <UserInterface.h>
//#include <GUI/Windows/ProjectManager.h>

class Program
{
public:
	Program(HMODULE hModule)
		: m_hModule(hModule)
	{
		m_dir = FS::File::getModule(hModule).getDirectory();
		m_projectManager = new ::ProjectManager(FS::File(getProgramDirectory(), "projects.json"));
		//m_userInterface = new UserInterface;
		CE::Hook::init();
	}

	void start() {
		getProjectManager()->loadProjects();
		//getUI()->getWindowManager()->addWindow(new GUI::Window::ProjectManagerWin(getProjectManager()));
	}

	FS::Directory& getProgramDirectory() {
		return m_dir;
	}

	::ProjectManager* getProjectManager() {
		return m_projectManager;
	}

	/*UserInterface* getUI() {
		return m_userInterface;
	}*/

	HMODULE getModule() {
		return m_hModule;
	}
private:
	HMODULE m_hModule;
	FS::Directory m_dir;
	::ProjectManager* m_projectManager;
	//UserInterface* m_userInterface;
};

extern Program* g_program;
static Program* getProgram() {
	return g_program;
}