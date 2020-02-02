#pragma once
#include "Shared/GUI/Windows/Templates/ItemList.h"
#include "GUI/Signature.h"
#include <Manager/FunctionManager.h>
#include <FunctionTag/FunctionTag.h>
#include "../ItemControlPanels/FunctionCP.h"
#include "../ProjectWindow.h"

using namespace CE;

namespace GUI::Window
{
	class FunctionList : public Template::ItemList
	{
	public:
		class FunctionFilter : public Filter
		{
		public:
			FunctionFilter(const std::string& name, FunctionList* functionList)
				: Filter(name), m_functionList(functionList)
			{}

			virtual bool checkFilter(API::Function::Function* function) = 0;

		protected:
			FunctionList* m_functionList;
		};

		class CategoryFilter : public FunctionFilter
		{
		public:
			Elements::List::MultiCombo* m_categoryList = nullptr;

			enum class Category : int
			{
				All					= -1,
				Not					= 0,

				Function			= 1 << 0,
				Method				= 1 << 1,
				StaticMethod		= 1 << 2,
				VirtualMethod		= 1 << 3,
				Constructor			= 1 << 4,
				Destructor			= 1 << 5,
				VirtualDestructor	= 1 << 6,

				Virtual				= VirtualMethod | VirtualDestructor
				
			};

			inline static std::vector<std::pair<std::string, Category>> m_categories = {
				{ std::make_pair("Function", Category::Function) },
				{ std::make_pair("Method", Category::Method) },
				{ std::make_pair("StaticMethod", Category::StaticMethod) },
				{ std::make_pair("VirtualMethod", Category::VirtualMethod) },
				{ std::make_pair("Constructor", Category::Constructor) },
				{ std::make_pair("Destructor", Category::Destructor) },
				{ std::make_pair("VirtualDestructor", Category::VirtualDestructor) },
				{ std::make_pair("Virtual", Category::Virtual) }
			};

			CategoryFilter(FunctionList* functionList, const StyleSettings& style)
				: FunctionFilter("Category filter", functionList)
			{
				buildHeader("Filter function by category.");
				beginBody()
					.addItem
					(
						(new Elements::List::MultiCombo("",
							new Events::EventUI(EVENT_LAMBDA(info) {
								updateFilter();
							})
						))
						->setWidth(style.m_leftWidth - 10),
						(Item**)& m_categoryList
					);

				for (auto& cat : m_categories) {
					m_categoryList->addSelectable(cat.first, true);
				}
			}

			void updateFilter() {
				int categorySelected = 0;
				for (int i = 0; i < m_categories.size(); i++) {
					if (m_categoryList->isSelected(i)) {
						categorySelected |= 1 << i;
					}
				}
				m_categorySelected = (Category)categorySelected;
				m_functionList->update();
			}

			bool checkFilter(API::Function::Function* function) override {
				return ((int)m_categorySelected & (int)m_categories[(int)function->getDeclaration()->getFunctionDecl()->getRole()].second) != 0;
			}

			bool isDefined() override {
				return true;
			}

		private:
			Category m_categorySelected = Category::All;
		};

		class ClassFilter : public FunctionFilter
		{
		public:
			ClassFilter(FunctionList* functionList)
				: FunctionFilter("Class filter", functionList)
			{
				buildHeader("Filter function by class.");
				beginBody()
					.text("class settings");
			}

			bool checkFilter(API::Function::Function* function) override {
				if (function->isFunction())
					return false;

				auto method = function->getMethod();
				if (method->getClass()->getId() != m_class->getClass()->getId())
					return false;

				return true;
			}

			bool isDefined() override {
				return m_class != nullptr;
			}

			void setClass(API::Type::Class* Class) {
				m_class = Class;
			}
		private:
			API::Type::Class* m_class = nullptr;
		};

		class FuncTagFilter : public FunctionFilter
		{
		public:
			FuncTagFilter(FunctionList* functionList)
				: FunctionFilter("Function tag filter", functionList)
			{
				buildHeader("Filter function by tag.");
				beginBody()
					.text("tag settings");
			}

			bool checkFilter(API::Function::Function* function) override {
				auto collection = m_functionList->m_funcManager->getFunctionTagManager()->getTagCollectionByDecl(function);
				return collection.contains(getTagCollection());
			}

			bool isDefined() override {
				return !m_collection.empty();
			}

			Function::Tag::TagCollection& getTagCollection() {
				return m_collection;
			}
		private:
			Function::Tag::TagCollection m_collection;
		};

		class FunctionItem : public Item
		{
		public:
			FunctionItem(API::Function::Function* function, Events::Event* event)
			{
				beginHeader()
					.addItem(
						new Units::Signature(function,
							new Events::EventUI(EVENT_LAMBDA(info) {
								
							}),
							new Events::EventUI(EVENT_LAMBDA(info) {

							}),
							new Events::EventUI(EVENT_LAMBDA(info) {
								auto argId = m_signature->m_argumentSelectedIdx;

							})
						),
						(GUI::Item**)& m_signature
					);

				beginBody()
					.text("Signature: ")
						.sameLine()
						.addItem(m_signature)
					.newLine()
					.newLine()
					.addItem(
						new Elements::Button::ButtonStd(
							"Open control panel",
							new Events::EventHook(event, function)
						)
					);

				m_signature->setCanBeRemoved(false);
			}

			~FunctionItem() {
				delete m_signature;
			}
		private:
			//MY TODO: может быть краш при удалении объекта, если он принадлежит нескольким родител€м. т.е. бита€ ссылка. ¬роде решил
			Units::Signature* m_signature;
		};

		FunctionList(FunctionManager* funcManager, const StyleSettings& style = StyleSettings())
			: m_funcManager(funcManager), ItemList("Function list", style)
		{
			addFunctionFilter(new CategoryFilter(this, style));
			addFunctionFilter(new ClassFilter(this));
			addFunctionFilter(new FuncTagFilter(this));

			m_openFunctionCP = new Events::EventUI(EVENT_LAMBDA(info) {
				auto sender = static_cast<Events::EventHook*>(info->getSender());
				auto function = (API::Function::Function*)sender->getUserDataPtr();

				getParent()->getMainContainer().clear();
				getParent()->getMainContainer().addItem((new Widget::FunctionCP(function))->getMainContainerPtr());
			});
			m_openFunctionCP->setCanBeRemoved(false);
		}

		~FunctionList() {
			delete m_openFunctionCP;
		}

		void addFunctionFilter(FunctionFilter* filter) {
			addFilter(filter);
			m_funcFiltes.push_back(filter);
		}

		void onSearch(const std::string& value) override
		{
			clear();
			int maxCount = 300;
			for (auto& it : m_funcManager->getFunctions()) {
				if (checkOnInputValue(it.second, value) && checkAllFilters(it.second)) {
					add(new FunctionItem(it.second, m_openFunctionCP));//MY TODO*: ленива€ загрузка, при открытии только
				}
				if (--maxCount == 0)
					break;
			}
		}

		bool checkOnInputValue(API::Function::Function* function, const std::string& value) {
			return Generic::String::ToLower(function->getFunction()->getName())
				.find(Generic::String::ToLower(value)) != std::string::npos;
		}

		bool checkAllFilters(API::Function::Function* function) {
			for (auto filter : m_funcFiltes) {
				if (filter->isDefined() && !filter->checkFilter(function)) {
					return false;
				}
			}
			return true;
		}

		FunctionManager* m_funcManager;
	private:
		std::list<FunctionFilter*> m_funcFiltes;
		Events::Event* m_openFunctionCP;
	};
};