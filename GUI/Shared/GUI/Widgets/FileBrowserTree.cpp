#include "FileBrowserTree.h"

using namespace GUI::Widget;

FileBrowserTree::~FileBrowserTree() {
	if (m_selectFileEvent != nullptr)
		delete m_selectFileEvent;
	if (m_rightMouseClickFile != nullptr)
		delete m_rightMouseClickFile;
	if (m_rightMouseClickDir != nullptr)
		delete m_rightMouseClickDir;
}

void FileBrowserTree::fillMainDir(Directory* dir)
{
	auto items = dir->getDir().getItems();
	items.sort([](const std::shared_ptr<FS::Item>& a, const std::shared_ptr<FS::Item>& b) {
		return (int)a->isDir() >= (int)b->isDir();
	});

	if (items.size() > 0) {
		for (auto it : items) {
			if (it->isDir()) {
				auto curDir = (FS::Directory*)it.get();
				if (doesNewDirRequireName(*curDir) || doesItemRequireRename(*curDir))
				{
					auto newDirElem = new DirToRename(
						*curDir,
						Events::Listener(
							std::function([&](Events::ISender* sender) {
								update();
							})
						),
						getOldNameOfItem(*curDir)
					);
					dir->addItem(newDirElem);
					fillMainDir(newDirElem);
				}
				else {
					auto newDirElem = new Directory(curDir->getName(), *curDir, m_rightMouseClickDir);
					dir->addItem(newDirElem);
					fillMainDir(newDirElem);
				}
			}
			else {
				auto curFile = (FS::File*)it.get();
				if (doesNewFileRequireName(*curFile) || doesItemRequireRename(*curFile))
				{
					dir->addItem(
						new FileToRename(
							curFile->getFullname(),
							Events::Listener(
								std::function([&](Events::ISender* sender) {
									update();
								})
							),
							getOldNameOfItem(*curFile)
						)
					);
				}
				else {
					dir->addItem(
						new File(curFile->getFullname(), m_selectFileEvent, m_rightMouseClickFile)
					);
				}
			}
		}
	}
}

void FileBrowserTree::buildTree()
{
	getMainDirPtr()->clear();
	fillMainDir(getMainDirPtr());
}
