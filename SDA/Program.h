#pragma once
#include <main.h>

namespace CE
{
	class ProjectManager;

	class Program
	{
		ProjectManager* m_projectManager;
	public:
		Program()
		{
			m_projectManager = new ProjectManager(this);
		}

		const fs::path& getExecutableDirectory() {
			return fs::path();
		}

		ProjectManager* getProjectManager() {
			return m_projectManager;
		}
	};
};