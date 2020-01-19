#pragma once

#include "../../Items/IWindow.h"

namespace GUI::Window::Template
{
	template<
		int windowsHeight		= 300,
		int divLeft				= 200,
		int divRight			= 500
	>
	class Manager : public IWindow
	{
	protected:
		inline static const int m_windowsHeight = windowsHeight;
		inline static const int m_divLeft = divLeft;
		inline static const int m_divRight = divRight;
			
		static void makeMainContainer(Container& parent, Container* bodyLeft, Container* bodyRight)
		{
			parent
			.beginChild("##body")
				.setWidth(0)
				.setHeight(windowsHeight + 5)
				.setColor(ImGuiCol_Separator, ColorRGBA(0x0))
				.setColor(ImGuiCol_SeparatorActive, ColorRGBA(0x0))
				.setColor(ImGuiCol_SeparatorHovered, ColorRGBA(0x0))
				.separator()
				.beginTable().setBorder(false)
					.beginHeader()
						.beginTD(m_divLeft + 10)
							.beginChild("##leftpane").setWidth(m_divLeft).setHeight(m_windowsHeight).setBorder(true)
								.addItem(bodyLeft)
							.end()
						.endTD()
						
						.beginTD(m_divRight + 10)
							.beginChild("##rightpane").setWidth(m_divRight).setHeight(m_windowsHeight).setBorder(true)
								.addItem(bodyRight)
							.end()
						.endTD()
					.endHeader()
				.end()
			.end();
		}

		Manager(std::string name)
			: IWindow(name, new Container)
		{
			(*this)
				.setFlags(ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize)
				.setWidth(m_divLeft + m_divRight + 40)
				.setHeight(m_windowsHeight + 40);
		}
	};

	//different sizes
	using ManagerStd = Manager<>;
};