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
		class FunctionFilter : public FilterManager::Filter
		{
		public:
			FunctionFilter(const std::string& name, FunctionList* functionList)
				: Filter(functionList->getFilterManager(), name), m_functionList(functionList)
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
				{ std::make_pair("Static method", Category::StaticMethod) },
				{ std::make_pair("Virtual method", Category::VirtualMethod) },
				{ std::make_pair("Constructor", Category::Constructor) },
				{ std::make_pair("Destructor", Category::Destructor) },
				{ std::make_pair("Virtual destructor", Category::VirtualDestructor) },
				{ std::make_pair("Virtual", Category::Virtual) }
			};

			CategoryFilter(FunctionList* functionList)
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
						->setWidth(functionList->m_styleSettings->m_leftWidth - 10),
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
				onChanged();
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

		class FunctionFilterCreator : public FilterManager::FilterCreator
		{
		public:
			FunctionFilterCreator(FunctionList* funcList)
				: m_funcList(funcList), FilterCreator(funcList->getFilterManager())
			{
				addItem("Category filter");
				addItem("Class filter");
				addItem("Tag filter");
			}

			FilterManager::Filter* createFilter(int idx) override
			{
				switch (idx)
				{
				case 0: return new CategoryFilter(m_funcList);
				case 1: return new ClassFilter(m_funcList);
				case 2: return new FuncTagFilter(m_funcList);
				}
				return nullptr;
			}

		private:
			FunctionList* m_funcList;
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
							new Events::EventHook(event, function),
							nullptr
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

		FunctionList(FunctionManager* funcManager)
			: m_funcManager(funcManager), ItemList("Function list", new FunctionFilterCreator(this))
		{
			getFilterManager()->addFilter(new CategoryFilter(this));
			getFilterManager()->addFilter(new ClassFilter(this));
			getFilterManager()->addFilter(new FuncTagFilter(this));

			m_openFunctionCP = new Events::EventUI(EVENT_LAMBDA(info) {
				auto message = std::dynamic_pointer_cast<Events::EventHookedMessage>(info);
				auto function = (API::Function::Function*)message->getUserDataPtr();

				getParent()->getMainContainer().clear();
				getParent()->getMainContainer().addItem((new Widget::FunctionCP(function))->getMainContainerPtr());
			});
			m_openFunctionCP->setCanBeRemoved(false);
		}

		~FunctionList() {
			delete m_openFunctionCP;
		}

		void onSearch(const std::string& value) override
		{
			clear();
			int maxCount = 300;
			for (auto& it : m_funcManager->getFunctions()) {
				if (checkOnInputValue(it.second, value) && checkAllFilters(it.second)) {
					add(createFuncItem(it.second, m_openFunctionCP));//MY TODO*: ленива€ загрузка, при открытии только
				}
				if (--maxCount == 0)
					break;
			}
		}

		virtual FunctionItem* createFuncItem(API::Function::Function* function, Events::Event* event) {
			return new FunctionItem(function, event);
		}

		bool checkOnInputValue(API::Function::Function* function, const std::string& value) {
			return Generic::String::ToLower(function->getFunction()->getName())
				.find(Generic::String::ToLower(value)) != std::string::npos;
		}

		bool checkAllFilters(API::Function::Function* function) {
			return getFilterManager()->check([&function](FilterManager::Filter* filter) {
				return static_cast<FunctionFilter*>(filter)->checkFilter(function);
			});
		}

		FunctionManager* m_funcManager;
	private:
		Events::Event* m_openFunctionCP;
	};

	class FuncSelectList : public FunctionList
	{
	public:
		class FunctionItemWithCheckBox : public FunctionItem
		{
		public:
			FunctionItemWithCheckBox(API::Function::Function* function, Events::Event* event, bool selected, Events::Event* eventSelectFunction)
				: FunctionItem(function, event)
			{
				(*m_header)
					.beginReverseInserting()
						.sameLine()
						.addItem(new Elements::Generic::Checkbox("", selected, eventSelectFunction))
					.endReverseInserting();
			}
		};

		FuncSelectList(FunctionManager* funcManager, Events::Event* eventSelectFunctions)
			: FunctionList(funcManager)
		{
			m_eventSelectFunction = new Events::EventUI(EVENT_LAMBDA(info) {
				auto message = std::dynamic_pointer_cast<Events::EventHookedMessage>(info);
				auto chekbox = static_cast<Elements::Generic::Checkbox*>(message->getRealSender());
				auto function = (API::Function::Function*)message->getUserDataPtr();
				if (chekbox->isSelected()) {
					m_selectedFunctions.push_back(function);
				}
				else {
					m_selectedFunctions.remove(function);
				}
			});

			class UpdSelectInfo : public Container
			{
			public:
				UpdSelectInfo(FuncSelectList* funcSelList, Events::Event* event)
					: m_funcSelList(funcSelList)
				{
					newLine();
					newLine();
					separator();
					addItem(m_button = new Elements::Button::ButtonStd("Select", event));
				}

				void render() override {
					Container::render();
					m_button->setName("Select " + std::to_string(m_funcSelList->getSelectedFuncCount()) + " functions");
				}

				bool isShown() override {
					return m_funcSelList->getSelectedFuncCount() > 0;
				}
			private:
				FuncSelectList* m_funcSelList;
				Elements::Button::ButtonStd* m_button;
			};

			(*m_underFilterCP)
				.addItem(new UpdSelectInfo(this, eventSelectFunctions));
		}

		FunctionItem* createFuncItem(API::Function::Function* function, Events::Event* event) override {
			return new FunctionItemWithCheckBox(function, event, isFunctionSelected(function), new Events::EventHook(m_eventSelectFunction, function));
		}

		bool isFunctionSelected(API::Function::Function* function) {
			for (auto func : getSelectedFunctions()) {
				if (func == function)
					return true;
			}
			return false;
		}

		int getSelectedFuncCount() {
			return getSelectedFunctions().size();
		}

		std::list<API::Function::Function*>& getSelectedFunctions() {
			return m_selectedFunctions;
		}
	private:
		std::list<API::Function::Function*> m_selectedFunctions;
		Events::Event* m_eventSelectFunction;
	};
};