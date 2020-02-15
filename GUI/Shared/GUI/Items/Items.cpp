#include "items.h"

using namespace GUI;

//MY TODO: here errors
Container& Container::clear() {
	for (auto it : m_items) {
		it->destroy();
	}
	m_items.clear();
	return *this;
}

Container& Container::addItem(Item* item) {
	if (m_reverseInsert) {
		m_items.push_front(item);
	}
	else {
		m_items.push_back(item);
	}
	item->setParent(this);
	return *this;
}

Container& Container::addItem(Item* item, Item** ptr)
{
	*ptr = item;
	return addItem(item);
}

Container& Container::sameLine(float spacing) {
	addItem(new Elements::Generic::SameLine(spacing));
	return *this;
}

Container& Container::newLine() {
	addItem(new Elements::Generic::NewLine);
	return *this;
}

Container& Container::separator()
{
	addItem(new Elements::Generic::Separator);
	return *this;
}

Container& Container::text(std::string value)
{
	Elements::Text::Text* ptr = nullptr;
	return text(value, &ptr);
}

Container& Container::sameText(std::string value)
{
	sameLine(0.0f);
	return text(value);
}

Container& Container::text(std::string value, ColorRGBA color)
{
	addItem(
		new Elements::Text::ColoredText(value, color)
	);
	return *this;
}

Container& Container::sameText(std::string value, ColorRGBA color)
{
	sameLine(0.0f);
	return text(value, color);
}

Container& Container::text(std::string value, Elements::Text::Text** item)
{
	*item = new Elements::Text::Text(value);
	addItem(*item);
	return *this;
}

#ifdef GUI_IS_MULTIPLAYER
Container& Container::ftext(const char* value, ...)
{
	va_list argPtr;
	va_start(argPtr, value);
	addItem(
		(new Elements::Text::FormatedText)
			->parse(value, argPtr)
	);
	va_end(argPtr);
	return *this;
}
#endif

Container& Container::removeLastItem() {
	if (getItems().size() > 0) {
		auto item = *(--getItems().end());
		item->destroy();

		getItems().pop_back();
	}
	return *this;
}

Container& Container::beginContainer() {
	Container* ptr = nullptr;
	return beginContainer(&ptr);
}

Container& Container::beginContainer(Container** ptr)
{
	*ptr = new Container;
	addItem(*ptr);
	return **ptr;
}

Table::Table& Container::beginTable()
{
	Table::Table* ptr = nullptr;
	return beginTable(&ptr);
}

Table::Table& Container::beginTable(Table::Table** ptr)
{
	*ptr = new Table::Table;
	addItem(*ptr);
	return **ptr;
}

ChildContainer& Container::beginChild()
{
	ChildContainer* ptr = nullptr;
	return beginChild(&ptr);
}

ChildContainer& Container::beginChild(ChildContainer** ptr)
{
	*ptr = new ChildContainer;
	addItem(*ptr);
	return **ptr;
}

PopupContainer& GUI::Container::beginPopup(PopupContainer** ptr)
{
	*ptr = new PopupContainer;
	addItem(*ptr);
	return **ptr;
}

TabBar& Container::beginTabBar(std::string name)
{
	TabBar* ptr = nullptr;
	return beginTabBar(name, &ptr);
}

TabBar& Container::beginTabBar(std::string name, TabBar** ptr)
{
	*ptr = new TabBar(name);
	addItem(*ptr);
	return **ptr;
}

ColContainer& Container::beginColContainer(std::string name)
{
	ColContainer* ptr = nullptr;
	return beginColContainer(name, &ptr);
}

ColContainer& Container::beginColContainer(std::string name, ColContainer** ptr)
{
	*ptr = new ColContainer(name);
	addItem(*ptr);
	return **ptr;
}

Container& Container::addList(List* list)
{
	List* ptr = nullptr;
	return addList(list, &ptr);
}

Container& Container::addList(List* list, List** ptr)
{
	*ptr = list;
	addItem(list);
	return *this;
}

TreeNode& Container::beginTreeNode(std::string name)
{
	TreeNode* ptr = nullptr;
	return beginTreeNode(name, &ptr);
}

TreeNode& Container::beginTreeNode(std::string name, TreeNode** ptr)
{
	*ptr = new TreeNode(name);
	addItem(*ptr);
	return **ptr;
}

MenuContainer& Container::beginMenu(std::string name)
{
	MenuContainer* ptr = nullptr;
	return beginMenu(name, &ptr);
}

MenuContainer& Container::beginMenu(std::string name, MenuContainer** ptr)
{
	*ptr = new MenuContainer(name);
	addItem(*ptr);
	return **ptr;
}

ImGuiContainer& GUI::Container::beginImGui(const std::function<void()> renderFunction)
{
	auto ptr = new ImGuiContainer(renderFunction);
	addItem(ptr);
	return *ptr;
}

Container& Container::end() {
	return *(Container*)getParent();
}

Table::TR& Container::endTD() {
	return *(Table::TR*)getParent();
}


List::~List() {
	for (auto it : m_elems) {
		delete it;
	}
}

List* List::addElem(Elements::List::Item* elem) {
	m_elems.push_back(elem);
	elem->setParent(this);
	elem->setValuePtr(&m_value);
	return this;
}

void List::render() {
	for (auto it : m_elems) {
		it->show();
	}
}


ListRadioBtn* ListRadioBtn::addRadioBtn(std::string name, int id)
{
	return (ListRadioBtn*)addElem(
		new Elements::List::RadioBtn(name, id, m_event)
	);
}

ListMenuItem* ListMenuItem::addMenuItem(std::string name, int id)
{
	return (ListMenuItem*)addElem(
		new Elements::List::MenuItem(name, id, m_event)
	);
}

MenuContainer& MenuContainer::menuItemWithShortcut(std::string name, std::string shortcut, Events::Event* event)
{
	Elements::Menu::Item* ptr = nullptr;
	menuItem(name, event, &ptr);
	ptr->setHintText(shortcut);
	return *this;
}

MenuContainer& MenuContainer::menuItem(std::string name, Events::Event* event)
{
	Elements::Menu::Item* ptr = nullptr;
	return menuItem(name, event, &ptr);
}

MenuContainer& MenuContainer::menuItem(std::string name, Events::Event* event, Elements::Menu::Item** item)
{
	*item = new Elements::Menu::Item(name, event);
	addItem(*item, (Item**)item);
	return *this;
}

MenuContainer& MenuContainer::menuItem(std::string name, Elements::Menu::Item** item)
{
	return menuItem(name, nullptr, item);
}

TabItem& TabBar::beginTabItem(std::string name)
{
	TabItem* ptr = nullptr;
	return beginTabItem(name, &ptr);
}

TabItem& TabBar::beginTabItem(std::string name, TabItem** ptr)
{
	*ptr = new TabItem(name);
	addItem(*ptr);
	return **ptr;
}


using namespace GUI::Events;
ISender* EventHookedMessage::getSender() {
	return m_newSender;
}

EventHandler* EventHookedMessage::getEventHandler() {
	return m_newSender->getEventHandler();
}

void* EventHookedMessage::getUserDataPtr() {
	return m_newSender->getUserDataPtr();
}