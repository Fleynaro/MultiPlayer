#pragma once

#include "Core/ScriptLang/ScriptManager.h"
#include "../../Items/IWindow.h"
#include "../../Widgets/FileBrowserTree.h"
#include "../../Widgets/SdkClassListSearch.h"
#include "../../Widgets/GameNativeListSearch.h"
#include "../../Widgets/GameAnimListSearch.h"
#include "../../Widgets/CodeEditor/CodeEditor.h"
#include "../GamePoolManager/GamePoolManagerWin.h"

#include "Game/GameInput.h"

namespace GUI::Window
{
	class ScriptEditorWin : public IWindowWithMenu
	{
		inline static const int fileBrowserWidth = 250;
		inline static const int fileBrowserHeight = 300;
		inline static const int API_listSearchHeight = 350;
		friend class Input;
	public:
		class Tab
			: public GUI::TabItem, public Events::OnClose<Tab>
		{
		public:
			Tab(std::string name)
				: GUI::TabItem(name)
			{}

			void render() override {
				bool is_notClosed = true;
				m_open = ImGui::BeginTabItem(getName().c_str(), &is_notClosed);
				if (ImGui::IsItemHovered())
					ImGui::SetTooltip(getEditor()->getFile().getPath().c_str());
				
				sendRightMouseClickEvent();
				if (isOpen()) {
					Container::render();
					ImGui::EndTabItem();
				}

				if (!is_notClosed) {
					sendCloseEvent();
				}
			}

			Tab& setEditor(Widget::CodeFileEditor* editor) {
				m_editor = editor;
				return *this;
			}

			Widget::CodeFileEditor* getEditor() {
				return m_editor;
			}
		private:
			Widget::CodeFileEditor* m_editor = nullptr;
		};

		class SdkClassListSearchWin : public IWindow
		{
		public:
			SdkClassListSearchWin(Widget::SdkClassListSearch* widget)
				: IWindow("SDK Classes")
			{
				//setWidth(400);
				//setHeight(300);
				getMainContainer()
					.addItem(widget->getMainContainerPtr());
			}
		};

		class GameNativeListSearchWin : public IWindow
		{
		public:
			GameNativeListSearchWin(Widget::GameNativeListSearch* widget)
				: IWindow("Game natives")
			{
				//setWidth(400);
				//setHeight(300);
				getMainContainer()
					.addItem(widget->getMainContainerPtr());
			}
		};

		class GameAnimsListSearchWin : public IWindow
		{
		public:
			GameAnimsListSearchWin(Widget::GameAnimListSearch* widget)
				: IWindow("Game animations")
			{
				//setWidth(400);
				//setHeight(300);
				getMainContainer()
					.addItem(widget->getMainContainerPtr());
			}
		};

		class Input : public IGameEventInput
		{
		public:
			Input(ScriptEditorWin* window)
				: m_window(window)
			{
				setPriority(Priority::VERY_HIGH);
				GameInput::addEventHandler(this);
			}
			~Input() {
				GameInput::removeEventHandler(this);
			}
			void keyDown(KEY keyCode) override
			{
				if (!m_window->isFocused() || keyCode == KeyCode::Control)
					return;

				if (m_lCtrlPressed)
				{
					switch (keyCode)
					{
					case KeyCode::S:
						m_window->CALL_EVENT_METHOD(save, nullptr);
						break;
					case KeyCode::Z:
						m_window->CALL_EVENT_METHOD(undo, nullptr);
						break;
					case KeyCode::Y:
						m_window->CALL_EVENT_METHOD(redo, nullptr);
						break;
					/*case KeyCode::X:
						m_window->CALL_EVENT_METHOD(cut, nullptr);
						break;
					case KeyCode::C:
						m_window->CALL_EVENT_METHOD(copy, nullptr);
						break;
					case KeyCode::V:
						m_window->CALL_EVENT_METHOD(paste, nullptr);
						break;*/
					}
				}

				if (keyCode == KeyCode::Shift && m_lAltPressed
					|| keyCode == KeyCode::Space && m_lCtrlPressed) {
					UserKeyboardList::switchToNext();
				}
			}
		private:
			ScriptEditorWin* m_window;
		};

		ScriptEditorWin(std::shared_ptr<Script::Mod> mod)
			: IWindowWithMenu("Script Editor"), m_mod(mod), m_inputListener(this)
		{
			buildFileBrowserTree();
			buildSdkClassListSearch();
			buildGameNativeListSearch();
			buildAnimListSearch();
			buildMenuBar();
			buildPopupFileWindow();
			buildPopupDirWindow();
			buildPopupTabWindow();
			setFont(FontSize::Standart);
			
			getMainContainer()
				.beginChild("Editor", &m_editor)
					.beginTable().setBorder(false)
						.beginHeader()
							.beginTD(fileBrowserWidth)
								.beginChild("##leftpane1").setHeight(fileBrowserHeight).setBorder(true)
									.addItem(
										m_fileBrowser->getMainContainerPtr()
									)
								.end()
								
								.beginChild("##leftpane2").setHeight(API_listSearchHeight).setBorder(true)
									.beginTabBar("API Browsing")
										.beginTabItem("SDK Classes")
											.text("Search classes")
											.addItem(
												m_sdkClassListSearch->getMainContainerPtr()
											)
											.separator().addItem(
												new Elements::Button::ButtonStd(
													"Open window",
													new Events::EventStd(EVENT_METHOD_PASS(openSDK))
												)
											)
										.backToTabBar()
									
										.beginTabItem("Natives")
											.text("Search natives")
											.addItem(
												m_gameNativeListSearch->getMainContainerPtr()
											)
											.separator().addItem(
												new Elements::Button::ButtonStd(
													"Open window",
													new Events::EventStd(EVENT_METHOD_PASS(openNatives))
												)
											)
										.backToTabBar()

										.beginTabItem("Anims")
											.text("Search animations")
											.addItem(
												m_gameAnimListSearch->getMainContainerPtr()
											)
											.separator().addItem(
												new Elements::Button::ButtonStd(
													"Open window",
													new Events::EventStd(EVENT_METHOD_PASS(openAnims))
												)
											)
										.end()
									.end()
								.end()

							.endTD()
						
							.beginTD()
								.beginChild("##rightpane").setBorder(true)
									.beginTabBar("tab bar", &m_editorArea)
									.end()
									//.ftext("{H2}Select any file to begin editing")
								.end()
							.endTD()
						.endHeader()
					.end()
				.end()
				.addItem(new Elements::Text::FormatedText, (Item **)& m_statusBar);

			/*m_sdkClassListSearch->getMainContainer()
				.setFont(Font::Tahoma_small);*/
		}
		~ScriptEditorWin() {
			delete m_fileBrowser;
			delete m_sdkClassListSearch;
			delete m_popupFileWindow;
			delete m_popupDirWindow;
			delete m_popupTabWindow;
			for (auto it : m_editors) {
				delete it;
			}
		}

		void buildFileBrowserTree()
		{
			m_fileBrowser = new Widget::FileBrowserTree(
				new Widget::FileBrowserTree::Directory(
					m_mod->getDirectory().getName(),
					m_mod->getDirectory()
				),
				new Events::EventStd(EVENT_METHOD_PASS(selectFileToEdit)),
				new Events::EventStd(EVENT_METHOD_PASS(openFilePopupWin)),
				new Events::EventStd(EVENT_METHOD_PASS(openDirPopupWin))
			);
		}

		void buildSdkClassListSearch()
		{
			m_sdkClassListSearch = new Widget::SdkClassListSearch;
		}

		void buildGameNativeListSearch()
		{
			m_gameNativeListSearch = new Widget::GameNativeListSearch;
		}

		void buildAnimListSearch()
		{
			m_gameAnimListSearch = new Widget::GameAnimListSearch;
		}

		EVENT_METHOD(selectFileToEdit, info)
		{
			auto sender = (Widget::FileBrowserTree::File*)(Events::OnSpecial*)info->getSender();
			if (sender->getFile().exists())
			{
				if (isEditOpenedWithFile(sender->getFile())) {
					writeStatusMessage<M_ERROR>("the file has already opened in this editor.");
					return;
				}
				addEditor(sender->getFile());
				writeStatusMessage<M_NOTE>("the new editor opened.", 1000);
			}
		}

		Widget::FileBrowserTree::File* m_selectedFile = nullptr;
		EVENT_METHOD(openFilePopupWin, info)
		{
			m_selectedFile = (Widget::FileBrowserTree::File*)(Events::OnRightMouseClick<Widget::FileBrowserTree::File>*)info->getSender();
			Widget::PopupContextWindow::Open(m_popupFileWindow);
		}

		Widget::FileBrowserTree::Directory* m_selectedDir = nullptr;
		EVENT_METHOD(openDirPopupWin, info)
		{
			m_selectedDir = (Widget::FileBrowserTree::Directory*)(Events::OnRightMouseClick<Widget::FileBrowserTree::Directory>*)info->getSender();
			Widget::PopupContextWindow::Open(m_popupDirWindow);
		}

		void buildMenuBar()
		{
			getMenu()
				.beginMenu("File")
					.menuItemWithShortcut("Save", "Ctrl + S", new Events::EventStd(EVENT_METHOD_PASS(save)))
				.end()

				.beginMenu("Edit")
					.menuItemWithShortcut("Undo", "Ctrl + Z", new Events::EventStd(EVENT_METHOD_PASS(undo)))
					.menuItemWithShortcut("Redo", "Ctrl + Y", new Events::EventStd(EVENT_METHOD_PASS(redo)))
					.menuItemWithShortcut("Cut", "Ctrl + X", new Events::EventStd(EVENT_METHOD_PASS(cut)))
					.menuItemWithShortcut("Copy", "Ctrl + C", new Events::EventStd(EVENT_METHOD_PASS(copy)))
					.menuItemWithShortcut("Paste", "Ctrl + V", new Events::EventStd(EVENT_METHOD_PASS(paste)))
				.end()

				.beginMenu("View")
					.menuItem("File browser refresh", new Events::EventStd(EVENT_LAMBDA(info) { m_fileBrowser->update(); }))
					.beginMenu("Font size")
						.addList(
							(new ListMenuItem(
								1,
								new Events::EventStd(EVENT_METHOD_PASS(selectFontSize))
							))
							->addMenuItem("Small", 0)
							->addMenuItem("Standart", 1)
							->addMenuItem("Big", 2)
						)
					.end()
				.end()

				.beginMenu("Keyboard layout")
					.addList(new ListMenuItem(
						0,
						new Events::EventStd(EVENT_METHOD_PASS(selectKeyboardLayout))
					), (List**)&m_keyboardList)
				.end()

				.beginMenu("Window")
					.menuItemWithShortcut("SDK viewer", "List of SDK classes, its members", new Events::EventStd(EVENT_METHOD_PASS(openSDK)))
					.menuItemWithShortcut("Native viewer", "List of all game natives with descriptions", new Events::EventStd(EVENT_METHOD_PASS(openNatives)))
					.menuItemWithShortcut("Animation viewer", "List of all game animations you can play", new Events::EventStd(EVENT_METHOD_PASS(openAnims)))
					.menuItemWithShortcut("Pool manager", "List of game pools", new Events::EventStd(EVENT_METHOD_PASS(openPools)))
				.end()

				.beginMenu("Help")
					
				.end();

			buildKeyboardList();
		}

		EVENT_METHOD(openSDK, info)
		{
			addWindow(new SdkClassListSearchWin(m_sdkClassListSearch));
		}

		EVENT_METHOD(openNatives, info)
		{
			addWindow(new GameNativeListSearchWin(m_gameNativeListSearch));
		}

		EVENT_METHOD(openAnims, info)
		{
			addWindow(new GameAnimsListSearchWin(m_gameAnimListSearch));
		}

		EVENT_METHOD(openPools, info)
		{
			addWindow(new GamePoolManager);
		}

		ListMenuItem* m_keyboardList = nullptr;
		void buildKeyboardList() {
			int i = 0;
			for (auto it : UserKeyboardList::getItems()) {
				m_keyboardList->addMenuItem(
					it->getEngName(),
					i++
				);
			}
		}
		EVENT_METHOD(selectKeyboardLayout, info)
		{
			auto sender = (Elements::List::MenuItem*)info->getSender();
			UserKeyboardList::getItems()[
				sender->getValue()
			]->makeCurrent();
		}

		EVENT_METHOD(save, info)
		{
			if (getActiveEditor() == nullptr)
				return;
			getActiveEditor()->saveToFile();
			writeStatusMessage<M_SUCCESS>("the file has been saved.");
		}

		EVENT_METHOD(undo, info)
		{
			if (getActiveEditor() == nullptr)
				return;
			getActiveEditor()->getEditor().Undo();
		}

		EVENT_METHOD(redo, info)
		{
			if (getActiveEditor() == nullptr)
				return;
			getActiveEditor()->getEditor().Redo();
		}

		EVENT_METHOD(copy, info)
		{
			if (getActiveEditor() == nullptr)
				return;
			getActiveEditor()->getEditor().Copy();
		}

		EVENT_METHOD(paste, info)
		{
			if (getActiveEditor() == nullptr)
				return;
			getActiveEditor()->getEditor().Paste();
		}

		EVENT_METHOD(cut, info)
		{
			if (getActiveEditor() == nullptr)
				return;
			getActiveEditor()->getEditor().Cut();
		}

		void buildPopupFileWindow()
		{
			m_popupFileWindow = new Widget::PopupContextWindow("file");
			m_popupFileWindow->getPopupCtxWin()
				.menuItem("Open", new Events::EventStd(EVENT_METHOD_PASS(popFileWin_open)))
				.menuItem("Cut", new Events::EventStd(EVENT_METHOD_PASS(popFileWin_cut)))
				.menuItem("Copy", new Events::EventStd(EVENT_METHOD_PASS(popFileWin_copy)))
				.menuItem("Delete", new Events::EventStd(EVENT_METHOD_PASS(popFileWin_delete)))
				.menuItem("Rename", new Events::EventStd(EVENT_METHOD_PASS(popFileWin_rename)));
		}

		EVENT_METHOD(popFileWin_open, info)
		{
			if (m_selectedFile->getFile().exists()) {
				if (isEditOpenedWithFile(m_selectedFile->getFile())) {
					writeStatusMessage<M_ERROR>("the file has already opened in this editor.");
					return;
				}
				addEditor(m_selectedFile->getFile());
				writeStatusMessage<M_NOTE>("the new editor opened.", 1000);
			}
		}

		EVENT_METHOD(popFileWin_cut, info)
		{
			if (!m_selectedFile->getFile().exists())
				return;
			FS::ClipBoard::File::cut(m_selectedFile->getFile());
		}

		EVENT_METHOD(popFileWin_copy, info)
		{
			if (!m_selectedFile->getFile().exists())
				return;
			FS::ClipBoard::File::copy(m_selectedFile->getFile());
		}

		EVENT_METHOD(popFileWin_delete, info)
		{
			if (m_selectedFile->getFile().remove()) {
				m_fileBrowser->update();
			}
			else {
				writeStatusMessage<M_ERROR>("cannot delete the file.");
			}
		}

		EVENT_METHOD(popFileWin_rename, info)
		{
			if (!m_selectedFile->getFile().exists())
				return;

			if (m_selectedFile->getFile().rename(
				"rename_" + m_selectedFile->getFile().getName()
			)) {
				m_fileBrowser->update();
			}
		}

		void buildPopupDirWindow()
		{
			m_popupDirWindow = new Widget::PopupContextWindow("dir");
			m_popupDirWindow->getPopupCtxWin()
				.beginMenu("Add")
					.menuItem("New a file", new Events::EventStd(EVENT_METHOD_PASS(popDirWin_createFile)))
					.menuItem("New a directory", new Events::EventStd(EVENT_METHOD_PASS(popDirWin_createDir)))
				.end();
			m_popupDirWindow->getPopupCtxWin()
				.menuItem("Delete", new Events::EventStd(EVENT_METHOD_PASS(popDirWin_delete)))
				.menuItem("Paste", new Events::EventStd(EVENT_METHOD_PASS(popDirWin_paste)))
				.menuItem("Rename", new Events::EventStd(EVENT_METHOD_PASS(popDirWin_rename)));
		}

		EVENT_METHOD(popDirWin_createFile, info)
		{
			if (!m_selectedDir->getDir().exists())
				return;

			auto newFile = Widget::FileBrowserTree::getFreeFileInDir(
				m_selectedDir->getDir()
			);
			FS::ScriptFileDesc desc(newFile, std::ios::out);
			if (desc.isOpen()) {
				desc.setData("//input your code here");
				m_fileBrowser->update();
			}
			else {
				writeStatusMessage<M_ERROR>("a file was not created.");
			}
		}

		EVENT_METHOD(popDirWin_createDir, info)
		{
			if (!m_selectedDir->getDir().exists())
				return;

			auto newDir = Widget::FileBrowserTree::getFreeDirInDir(
				m_selectedDir->getDir()
			);
			if (newDir.createIfNotExists()) {
				m_fileBrowser->update();
			}
			else {
				writeStatusMessage<M_ERROR>("a dir was not created.");
			}
		}

		EVENT_METHOD(popDirWin_delete, info)
		{
			if (!m_selectedDir->getDir().exists())
				return;
			if (!std::filesystem::is_empty(m_selectedDir->getDir().getPath())) {
				writeStatusMessage<M_ERROR>("the dir was not removed. Delete all containing items into that.");
				return;
			}

			if (m_selectedDir->getDir().remove()) {
				m_fileBrowser->update();
			}
			else {
				writeStatusMessage<M_ERROR>("the dir was not removed.");
			}
		}

		EVENT_METHOD(popDirWin_rename, info)
		{
			if (!m_selectedDir->getDir().exists())
				return;

			if (m_selectedDir->getDir().rename(
				"rename_" + m_selectedDir->getDir().getName()
			)) {
				m_fileBrowser->update();
			}
			else {
				writeStatusMessage<M_ERROR>("the file was not renamed.");
			}
		}

		EVENT_METHOD(popDirWin_paste, info)
		{
			using namespace FS::ClipBoard;
			if (!File::isFileValid())
				return;
			
			File::pasteTo(
				FS::File(
					m_selectedDir->getDir(),
					"rename_" + File::getFile().getFullname()
				)
			);
			m_fileBrowser->update();
		}

		void addEditor(FS::File file) {
			auto editor = new Widget::CodeFileEditor(
				file.getFullname(),
				file,
				Widget::CodeFileEditor::getLangByFile(file)
			);
			editor->getMainContainer().setParent(this);
			m_editors.push_back(editor);
			updateEditorTabs();
		}

		void removeEditor(Widget::CodeFileEditor* editor) {
			m_editors.remove(editor);
			updateEditorTabs();
		}


		bool isEditOpenedWithFile(FS::File file) {
			for (auto it : m_editors) {
				if (it->getFile().getPath() == file.getPath()) {
					return true;
				}
			}
			return false;
		}

		void updateEditorTabs()
		{
			m_editorArea->clear();

			for (auto it : m_editors)
			{
				Tab* tab = new Tab(it->getFile().getFullname());
				(*tab)
					.setEditor(it)
					.addItem(it->getMainContainerPtr());

				tab->setRightMouseClickEvent(
					new Events::EventStd(EVENT_METHOD_PASS(openTabPopupWin))
				);

				tab->setCloseEvent(
					new Events::EventUI(EVENT_METHOD_PASS(closeTabPopupWin))
				);

				tab->setFont(m_font);

				m_editorArea->addItem(tab);
			}
		}

		Tab* m_selectedTab = nullptr;
		EVENT_METHOD(openTabPopupWin, info)
		{
			m_selectedTab = (Tab*)(GUI::TabItem*)info->getSender();
			Widget::PopupContextWindow::Open(m_popupTabWindow);
		}

		EVENT_METHOD(closeTabPopupWin, info)
		{
			auto tab = (Tab*)(Events::OnClose<Tab>*)info->getSender();
			auto editor = tab->getEditor();
			removeEditor(editor);
			delete editor;
		}

		void buildPopupTabWindow()
		{
			m_popupTabWindow = new Widget::PopupContextWindow("tab");
			m_popupTabWindow->getPopupCtxWin()
				.menuItem("Close", new Events::EventStd(EVENT_METHOD_PASS(popTabWin_close)));
		}

		EVENT_METHOD(popTabWin_close, info)
		{
			auto editor = m_selectedTab->getEditor();
			removeEditor(editor);
			delete editor;
		}

		Widget::CodeFileEditor* getActiveEditor() {
			for (auto it : m_editorArea->getItems()) {
				auto tab = (Tab*)it;
				if (tab->isOpen()) {
					return tab->getEditor();
				}
			}
			return nullptr;
		}


		enum StatusMessageType {
			M_SUCCESS,
			M_ERROR,
			M_NOTE
		};
		std::chrono::time_point<std::chrono::steady_clock> m_statusMessageTime;
		std::string m_statusMessage;

		template<StatusMessageType type = M_NOTE>
		void writeStatusMessage(std::string message, int ms = 3000) {
			m_statusMessageTime = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
			if constexpr (type == M_NOTE)
				m_statusMessage = "{b3e0ff}Note: ";
			else if constexpr (type == M_SUCCESS)
				m_statusMessage = "{b3ffcc}Success: ";
			else
				m_statusMessage = "{ffb3b3}Error: ";
			m_statusMessage += message;
		}


		void onRender() override
		{
			m_gameNativeListSearch->loadingCheckUpdate();
			m_gameAnimListSearch->loadingCheckUpdate();

			(*m_editor)
				.setWidth(getX() - 10)
				.setHeight(getY() - 75);

			auto activeEditor = getActiveEditor();
			
			m_statusBar->clear();
			if (m_statusMessageTime >= std::chrono::steady_clock::now())
			{
				m_statusBar->parse(m_statusMessage.c_str());
			}
			else if (activeEditor != nullptr)
			{
				m_statusBar->parse(activeEditor->getStatusInfo().c_str());
			}

			int curKeyBoard = UserKeyboardList::getCurrentId();
			if (curKeyBoard != -1)
			{
				m_keyboardList->setValue(curKeyBoard);
			}
		}

		Script::Mod* getScriptMod() {
			return m_mod.get();
		}

		enum class FontSize
		{
			Small,
			Standart,
			Big
		};
		void setFont(FontSize size) {
			switch (size)
			{
			case FontSize::Small:
				m_font = Font::Consolas_12;
				break;
			case FontSize::Standart:
				m_font = Font::Consolas_14;
				break;
			case FontSize::Big:
				m_font = Font::Consolas_16;
				break;
			}
		}
		EVENT_METHOD(selectFontSize, info)
		{
			auto sender = (Elements::List::MenuItem*)info->getSender();
			setFont((FontSize)sender->getValue());
			updateEditorTabs();
		}
	private:
		Input m_inputListener;
		std::shared_ptr<Script::Mod> m_mod;
		Widget::FileBrowserTree* m_fileBrowser = nullptr;
		Widget::SdkClassListSearch* m_sdkClassListSearch = nullptr;
		Widget::GameNativeListSearch* m_gameNativeListSearch = nullptr;
		Widget::GameAnimListSearch* m_gameAnimListSearch = nullptr;
		GUI::TabBar* m_editorArea = nullptr;
		std::list<Widget::CodeFileEditor*> m_editors;

		Widget::PopupContextWindow* m_popupFileWindow = nullptr;
		Widget::PopupContextWindow* m_popupDirWindow = nullptr;
		Widget::PopupContextWindow* m_popupTabWindow = nullptr;

		ChildContainer* m_editor = nullptr;
		Elements::Text::FormatedText* m_statusBar = nullptr;

		ImFont* m_font = nullptr;
	};
};