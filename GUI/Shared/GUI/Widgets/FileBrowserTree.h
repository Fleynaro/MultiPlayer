#pragma once

#include "../Items/IWidget.h"
#include "Utility/FileWrapper.h"

namespace GUI::Widget
{
	class FileBrowserTree : public Container
	{
	public:
		class Directory;
		class File;
		FileBrowserTree(Directory* mainDir, Events::Event* selectFileEvent = nullptr, Events::Event* rightMouseClickFile = nullptr, Events::Event* rightMouseClickDir = nullptr)
			: m_mainDir(mainDir), m_selectFileEvent(selectFileEvent), m_rightMouseClickFile(rightMouseClickFile), m_rightMouseClickDir(rightMouseClickDir)
		{
			addItem(mainDir);
			buildTree();

			getMainDirPtr()->open();
			getMainDirPtr()->getRightMouseClickEvent() += rightMouseClickDir;

			if (m_selectFileEvent != nullptr)
				m_selectFileEvent->setCanBeRemoved(false);
			if (m_rightMouseClickFile != nullptr)
				m_rightMouseClickFile->setCanBeRemoved(false);
			if (m_rightMouseClickDir != nullptr)
				m_rightMouseClickDir->setCanBeRemoved(false);
		}
		~FileBrowserTree();

		void update() {
			buildTree();
		}

		EVENT_METHOD(update, info) {
			update();
		}

		void buildTree();

		void fillMainDir(Directory* dir);

		std::string getRelativePath(FS::Item& item) {
			auto path = item.getPath();
			FS::File::exceptDirInPath(getMainDirPtr()->getDir(), path);
			return path;
		}

		void markDirAsCollapsed(FS::Directory& dir) {
			m_itemCollapsed.insert(getRelativePath(dir));
		}

		void unmarkDirAsCollapsed(FS::Directory& dir) {
			m_itemCollapsed.erase(getRelativePath(dir));
		}

		bool isDirMarkedAsCollapsed(FS::Directory& dir) {
			return m_itemCollapsed.find(getRelativePath(dir)) != m_itemCollapsed.end();
		}

		static std::string getOldNameOfItem(FS::Item& item) {
			std::string subStr("rename_");

			auto it = item.getName().find(subStr);
			if (it != std::string::npos) {
				return item.getName().erase(it, subStr.size());
			}
			return item.getName();
		}

		static bool doesItemRequireRename(FS::Item& item) {
			return std::regex_match(item.getName().c_str(), std::regex("^rename_.*"));
		}

		static bool doesNewFileRequireName(FS::File& file) {
			return std::regex_match(file.getNameWithoutFormat().c_str(), std::regex("^newFile\\d+$"));
		}

		static bool doesNewDirRequireName(FS::Directory& dir) {
			return std::regex_match(dir.getName().c_str(), std::regex("^newDir\\d+$"));
		}

		static FS::File getFreeFileInDir(FS::Directory dir) {
			FS::File resultFile;
			int i = 1;
			while (
				(resultFile = FS::File(dir, Generic::String::format("newFile%i.txt", i++))).exists()
			);
			return resultFile;
		}

		static FS::Directory getFreeDirInDir(FS::Directory dir) {
			FS::Directory resultDir;
			int i = 1;
			while (
				(resultDir = dir.next(Generic::String::format("newDir%i", i++))).exists()
			);
			return resultDir;
		}

		class File
			: public Elem,
			public Events::OnSpecial<File>,
			public Events::OnRightMouseClick<File>,
			public Attribute::Name<File>
		{
		public:
			File(std::string name, Events::Event* event = nullptr, Events::Event* rightClick = nullptr)
				: Attribute::Name<File>(name), Events::OnSpecial<File>(this, event), Events::OnRightMouseClick<File>(this, rightClick)
			{}

			Directory* getParentDir() {
				return (Directory*)getParent();
			}

			FS::File getFile() {
				return FS::File(getParentDir()->getDir(), getName());
			}

			void render() override {
				if (ImGui::Selectable(getName().c_str())) {
					sendSpecialEvent();
				}
				sendRightMouseClickEvent();
			}
		};

		class FileToRename
			: public File, public Attribute::Rename<FileToRename>
		{
		public:
			FileToRename(std::string name, Events::Event* event = nullptr, std::string preName = "")
				: File(name, event), Attribute::Rename<FileToRename>(preName)
			{}

			void render() override {
				renderInput();
			}

			void enterInput() override {
				if (getFile().rename(getInputName())) {
					sendSpecialEvent();
				}
			}
		};

		class Directory
			: public TreeNode, public Events::OnRightMouseClick<Directory>
		{
		public:
			Directory(std::string name, FS::Directory dir, Events::Event* rightClick = nullptr)
				: TreeNode(name, false), m_dir(dir), Events::OnRightMouseClick<Directory>(this, rightClick)
			{}

			FS::Directory& getDir() {
				return m_dir;
			}

			void render() override {
				if (isOpen()) {
					ImGui::SetNextTreeNodeOpen(true);
				}

				bool opened = ImGui::TreeNode(getName().c_str());
				sendRightMouseClickEvent();
				if (opened) {
					Container::render();
					ImGui::TreePop();
				}
			}
		protected:
			FS::Directory m_dir;
		};

		class DirToRename
			: public Directory,
			public Events::OnSpecial<DirToRename>,
			public Attribute::Rename<DirToRename>
		{
		public:
			DirToRename(FS::Directory dir, Events::Event* event = nullptr, std::string preName = "")
				: Directory("Enter a new name", dir), Events::OnSpecial<DirToRename>(this, event), Attribute::Rename<DirToRename>(preName)
			{}

			void render() override {
				renderInput();
				Directory::render();
			}

			void enterInput() override {
				if (getDir().rename(getInputName())) {
					sendSpecialEvent();
				}
			}
		};

		Directory* getMainDirPtr() {
			return m_mainDir;
		}
	protected:
		Directory* m_mainDir;
		Events::Event* m_selectFileEvent;
		Events::Event* m_rightMouseClickFile;
		Events::Event* m_rightMouseClickDir;

		std::set<std::string> m_itemCollapsed;
	};
};