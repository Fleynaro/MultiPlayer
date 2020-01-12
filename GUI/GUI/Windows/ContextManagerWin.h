#pragma once

#include "Templates/ManagerWin.h"
#include "Game/ScriptEngine/GameScriptEngine.h"
#include "../Windows/ScriptEditor/ScriptEditorWin.h"


namespace GUI::Window
{
	class ContextManager : public Template::ManagerStd
	{
		inline static const int m_bottomHeight = 150;
	public:
		ContextManager()
			: Template::ManagerStd("Context manager")
		{
			Template::ManagerStd::makeMainContainer(
				getMainContainer(),
				bodyLeft(),
				bodyRight()
			);

			this->setHeight(m_windowsHeight + m_bottomHeight + 40);
			getMainContainer()
				.beginChild("##bottom", &m_console)
					.setBorder(true)
					.setWidth(0)
					.setHeight(m_bottomHeight - 10)
				.end();
			m_console->setScrollbarToBottom();
		}

		std::string getContextTypeName(IGameScriptContext::Type type) {
			switch (type)
			{
			case IGameScriptContext::Type::Standart:
				return "standart";
			case IGameScriptContext::Type::JavaScript:
				return "javascript";
			case IGameScriptContext::Type::Lua:
				return "lua";
			}
			return "not";
		}

		bool isLangContext(IScriptLangContext::Type type) {
			return type == IScriptLangContext::Type::JavaScript || type == IScriptLangContext::Type::Lua;
		}

		std::string getContextTitle(IGameScriptContext* context) {
			return String::format(
				"Context %s #%i", getContextTypeName(context->getType()), context->m_info.getId()
			);
		}
	private:
		ChildContainer* m_console = nullptr;
		void updateConsole() {
			if (m_selected == nullptr)
				return;

			m_console->clear();
			for (auto it : m_selected->getConsoleLog()) {
				m_console->addItem(
					new Elements::Text::BulletText(
						Date::format(it.first, Date::View::Time) + ": " + it.second
					)
				);
			}
		}

		void onRender() override
		{
			m_contextsList->clear();
			generateContextsList();

			updateConsole();
		}

		Elements::List::ListBoxDyn* m_contextsList = nullptr;
		Container* bodyLeft()
		{
			Container* container = new Container;
			(*container)
				.text("Select a context")
				.addItem
				(
					(new Elements::List::ListBoxDyn("", 0,
						new Events::EventUI(EVENT_LAMBDA(info)
						{
							auto sender = (Elements::List::ListBoxDyn*)info->getSender();
							selectContext(
								(IGameScriptContext*)sender->getSelectedItemPtr()
							);
						})
					))
					->setWidth(m_divLeft - 15)
					->setHeight(-1),
					(Item**)& m_contextsList
				);
			return container;
		}

		std::string getSleepBtnName() {
			return m_selected->isSleeping() ? "Continue" : "Stop";
		}

		IGameScriptContext* m_selected = nullptr;
		Elements::Button::ButtonStd* m_sleepBtn = nullptr;
		void selectContext(IGameScriptContext* context) {
			m_selected = context;
			(*m_body)
				.clear()
				.text(String::format(
					"%s selected.", getContextTitle(context).c_str()
				))
				.newLine()
				.addItem(
					new Elements::Button::ButtonStd(
						getSleepBtnName(),
						new Events::EventUI(
							EVENT_LAMBDA(info) {
								if (!m_selected->isSleeping()) {
									m_selected->sleep(100000000, false);
								}
								else {
									m_selected->sleep(0, false);
								}
								m_sleepBtn->setName(getSleepBtnName());
							}
						)
					),
					(Item**)&m_sleepBtn
				)
				.sameLine().addItem(
					new Elements::Button::ButtonStd(
						"Reload",
						new Events::EventUI(
							EVENT_LAMBDA(info) {
								GameScriptEngine::reloadScriptExecutionContext(m_selected);
								selectContext(m_selected);
								return;
								//select in context list
								m_contextsList->clear();
								generateContextsList();
								m_contextsList->selectByPtr(m_selected);
							}
						)
					)
				)
				.sameLine().addItem(
					new Elements::Button::ButtonStd(
						"Clear console",
						new Events::EventUI(
							EVENT_LAMBDA(info) {
								m_selected->clearConsoleLog();
							}
						)
					)
				);


			if (isLangContext(context->getType())) {
				auto modContext = (IScriptLangContext*)context;
				(*m_body)
					.sameLine().addItem(
						new Elements::Button::ButtonStd(
							"Open editor",
							new Events::EventUI(
								EVENT_LAMBDA(info) {
									auto modContext = (IScriptLangContext*)m_selected;
									if (isEditorOpened(modContext))
										return;
									addWindow(
										new GUI::Window::ScriptEditorWin(
											modContext->getScriptModShrPtr()
										)
									);
								}
							)
						)
					)
					.ftext(
						String::format("{ccffff}Directory:{} %s\n{ccffff}Main file:{} %s\n{ccffff}Entry point:{} %s",
							modContext->getScriptMod()->getDirectory().getPath().c_str(),
							modContext->getScriptMod()->getMainExecutionFile().getFullname().c_str(),
							modContext->getScriptMod()->getEntryFunction().c_str()
						).c_str()
					);
			}
		}

		bool isEditorOpened(IScriptLangContext* ctx) {
			auto path = ctx->getScriptMod()->getDirectory().getPath();
			for (auto it : m_childs) {
				auto editorWin = (GUI::Window::ScriptEditorWin*)it;
				if (editorWin->getScriptMod()->getDirectory().getPath() == path) {
					return true;
				}
			}
			return false;
		}

		void generateContextsList() {
			for (auto it : GameScriptEngine::getContexts()) {
				m_contextsList->addItem(getContextTitle(it), it);
			}

			if (!GameScriptEngine::getContexts().empty() && m_selected == nullptr) {
				selectContext(
					*GameScriptEngine::getContexts().begin()
				);
			}
		}

		Container* m_body = nullptr;
		Container* bodyRight()
		{
			m_body = new Container;
			(*m_body)
				.text("Not any context created yet.")
				.addItem(
					new Elements::Button::ButtonStd(
						"Open test editor",
						new Events::EventUI(
							EVENT_LAMBDA(info) {
								addWindow(
									new GUI::Window::ScriptEditorWin(
										std::shared_ptr<Script::Mod>(new Script::Mod(
											FS::Directory("R:\\Rockstar Games\\Grand Theft Auto V\\FastLoader\\scripts\\testLua")
										))
									)
								);
							}
						)
					)
				);
			return m_body;
		}
	};
};