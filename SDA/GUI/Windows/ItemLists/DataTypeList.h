#pragma once
#include "Shared/GUI/Widgets/Template/ItemList.h"
#include "GUI/Type.h"
#include <Manager/FunctionManager.h>
#include "../ProjectWindow.h"

using namespace CE;

namespace GUI::Widget
{
	class DataTypeList : public Template::ItemList
	{
	public:
		class ListView : public IView
		{
		public:
			class ShortTypeItem : public Item
			{
			public:
				ShortTypeItem(API::Type::Type* type, Events::Event* eventClickOnName)
					: m_type(type)
				{
					addFlags(ImGuiTreeNodeFlags_Leaf, true);

					beginHeader()
						.addItem(new Units::Type(type->getType(), eventClickOnName));
				}

			private:
				API::Type::Type* m_type;
			};

			class TypeItem : public ShortTypeItem
			{
			public:
				TypeItem(API::Type::Type* type, Events::Event* eventClickOnName)
					: ShortTypeItem(type, eventClickOnName)
				{
					addFlags(ImGuiTreeNodeFlags_Leaf, false);

					beginBody()
						.addItem(
							new Elements::Button::ButtonStd(
								"Open control panel",
								new Events::EventUI(EVENT_LAMBDA(info) {
									openControlPanel();
								})
							)
						)
						.text(GUI::Units::Type::getTooltipDesc(type->getType(), false));
				}

				void openControlPanel();
			private:
				API::Type::Type* m_type;
			};

			ListView(DataTypeList* dataTypeList, TypeManager* typeManager, bool shortTypeItem = false)
				: m_dataTypeList(dataTypeList), m_typeManager(typeManager), m_shortTypeItem(shortTypeItem)
			{}

			int m_maxOutputDataTypeCount = 300;
			void onSearch(const std::string& value) override
			{
				getOutContainer()->clear();
				int maxCount = m_maxOutputDataTypeCount;

				for (auto& it : m_typeManager->getTypes()) {
					if (m_dataTypeList->checkOnInputValue(it.second, value) && m_dataTypeList->checkAllFilters(it.second)) {
						getOutContainer()->addItem(createItem(it.second));
					}
					if (--maxCount == 0)
						break;
				}
			}

			Item* createItem(API::Type::Type* type) {
				auto eventHandler = new Events::EventHook(m_dataTypeList->m_eventClickOnName, type);
				if (m_shortTypeItem) {
					return new ShortTypeItem(type, eventHandler);
				}
				return new TypeItem(type, eventHandler);
			}
		protected:
			TypeManager* m_typeManager;
			DataTypeList* m_dataTypeList;
			bool m_shortTypeItem = false;
		};
		friend class ListView;

		class TypeFilter : public FilterManager::Filter
		{
		public:
			TypeFilter(const std::string& name, DataTypeList* dataTypeList)
				: Filter(dataTypeList->getFilterManager(), name), m_dataTypeList(dataTypeList)
			{}

			virtual bool checkFilter(API::Type::Type* type) = 0;
		protected:
			DataTypeList* m_dataTypeList;
		};

		class CategoryFilter : public TypeFilter
		{
		public:
			Elements::List::MultiCombo* m_categoryList = nullptr;

			enum class Category : int
			{
				All			= -1,
				Not			= 0,

				Simple		= 1 << 0,
				Enum		= 1 << 1,
				Class		= 1 << 2,
				Typedef		= 1 << 3,
				Signature	= 1 << 4,

				Composed	= Enum | Class | Signature
			};

			inline static std::vector<std::pair<std::string, Category>> m_categories = {
				{ std::make_pair("Simple", Category::Simple) },
				{ std::make_pair("Enum", Category::Enum) },
				{ std::make_pair("Class", Category::Class) },
				{ std::make_pair("Typedef", Category::Typedef) },
				{ std::make_pair("Signature", Category::Signature) }
			};

			CategoryFilter(DataTypeList* dataTypeList)
				: TypeFilter("Category filter", dataTypeList)
			{
				buildHeader("Filter types by category.");
				beginBody()
					.addItem
					(
						(new Elements::List::MultiCombo("",
							new Events::EventUI(EVENT_LAMBDA(info) {
								updateFilter();
							})
						))
						->setWidth(dataTypeList->m_styleSettings.m_leftWidth - 10),
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

			bool checkFilter(API::Type::Type* type) override {
				return ((int)m_categorySelected & (int)m_categories[type->getType()->getGroup()].second) != 0;
			}

			bool isDefined() override {
				return true;
			}
		private:
			Category m_categorySelected = Category::All;
		};

		class TypeFilterCreator : public FilterManager::FilterCreator
		{
		public:
			TypeFilterCreator(DataTypeList* dataTypeList)
				: m_dataTypeList(dataTypeList), FilterCreator(dataTypeList->getFilterManager())
			{
				addItem("Category filter");
			}

			FilterManager::Filter* createFilter(int idx) override
			{
				switch (idx)
				{
				case 0: return new CategoryFilter(m_dataTypeList);
				}
				return nullptr;
			}

		private:
			DataTypeList* m_dataTypeList;
		};

		DataTypeList()
			: ItemList(new TypeFilterCreator(this))
		{
			getFilterManager()->addFilter(new CategoryFilter(this));
		}

		bool checkOnInputValue(API::Type::Type* type, const std::string& value) {
			return Generic::String::ToLower(type->getType()->getName())
				.find(Generic::String::ToLower(value)) != std::string::npos;
		}

		bool checkAllFilters(API::Type::Type* type) {
			return getFilterManager()->check([&type](FilterManager::Filter* filter) {
				return static_cast<TypeFilter*>(filter)->checkFilter(type);
			});
		}
		
		void setEventHandlerClickOnName(Events::Event* eventHandler) {
			m_eventClickOnName = eventHandler;
		}
	private:
		Events::Event* m_eventClickOnName;
	};
};

namespace GUI::Window
{
	class DataTypeList : public IWindow
	{
	public:
		DataTypeList(Widget::DataTypeList* dataTypeList = new Widget::DataTypeList)
			: IWindow("Data type list")
		{
			setMainContainer(dataTypeList);
		}

		~DataTypeList() {
			delete m_openFunctionCP;
		}

		Widget::DataTypeList* getList() {
			return static_cast<Widget::DataTypeList*>(getMainContainerPtr());
		}
	private:
		Events::EventHandler* m_openFunctionCP;
	};
};


namespace GUI::Widget
{
	class DataTypeInput : public Template::ItemInput
	{
	public:
		DataTypeInput(TypeManager* typeManager)
			: m_selectDataType(this)
		{
			m_dataTypeList = new DataTypeList;

			m_dataTypeList->setView(
				m_dataTypeListView = new DataTypeList::ListView(m_dataTypeList, typeManager, false)
			);
			m_dataTypeList->setParent(this);

			m_dataTypeShortListView = new DataTypeList::ListView(m_dataTypeList, typeManager, true);
			m_dataTypeShortListView->setOutputContainer(m_dataTypeShortList = new Container);
			m_dataTypeShortList->setParent(this);
			m_dataTypeShortListView->m_maxOutputDataTypeCount = 20;


			m_selectDataTypeEvent = new Events::EventUI(EVENT_LAMBDA(info) {
				auto message = std::dynamic_pointer_cast<Events::EventHookedMessage>(info);
				auto dataType = (API::Type::Type*)message->getUserDataPtr();

				m_selectedType = dataType->getType();
				m_focused = false;
				m_selectDataType.callEventHandler();
			});
			m_selectDataTypeEvent->setCanBeRemoved(false);
			m_dataTypeList->setEventHandlerClickOnName(m_selectDataTypeEvent);
		}

		~DataTypeInput() {
			m_dataTypeList->destroy();
			m_dataTypeShortList->destroy();
			delete m_dataTypeListView;
			delete m_dataTypeShortListView;
			delete m_selectDataTypeEvent;
		}

		void setSelectedType(CE::Type::Type* selectedType) {
			m_selectedType = selectedType;
		}

		CE::Type::Type* getSelectedType() {
			return m_selectedType;
		}

		bool isTypeSelected() {
			return m_selectedType != nullptr;
		}

		Events::Messager m_selectDataType;
	protected:
		std::string getPlaceHolder() override {
			if (!isTypeSelected())
				return "No selected type";
			return getSelectedType()->getDisplayName();
		}

		std::string toolTip() override {
			if (!isTypeSelected())
				return "please, select a type";
			return "type selected";
		}

		void onSearch(const std::string& text) {
			m_dataTypeShortListView->onSearch(text);
		}

		void renderShortView() override {
			m_dataTypeShortList->show();
			renderSelectables();
		}

		void renderSelectables() {
			if (isTypeSelected()) {
				if (ImGui::Selectable("Clear")) {
					m_selectedType = nullptr;
				}
			}

			if (!m_isWinOpen && ImGui::Selectable("More...")) {
				Window::DataTypeList* win;
				getWindow()->addWindow(
					win = new Window::DataTypeList(m_dataTypeList)
				);
				win->getCloseEvent() +=
					new Events::EventUI(
						EVENT_LAMBDA(info) {
					m_isWinOpen = false;
				}
				);
				m_isWinOpen = true;
				m_focused = false;
			}
		}

	private:
		DataTypeList* m_dataTypeList;
		DataTypeList::ListView* m_dataTypeListView;
		DataTypeList::ListView* m_dataTypeShortListView;
		Container* m_dataTypeShortList;
		CE::Type::Type* m_selectedType = nullptr;
		bool m_isWinOpen = false;
		Events::EventHandler* m_selectDataTypeEvent;
	};
};

namespace GUI::Window
{
	class DataTypeSelector
		: public IWindow
	{
	public:
		DataTypeSelector(TypeManager* typeManager)
			: IWindow("Select data type"), m_typeManager(typeManager)
		{
			setWidth(450);
			setHeight(300);
			setFlags(ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar);

			m_updateEvent = new Events::EventUI(EVENT_LAMBDA(info) {
				onUpdateInput();
			});
			m_updateEvent->setCanBeRemoved(false);

			getMainContainer()
				.text("Data type")
				.addItem(m_dataTypeInput = new Widget::DataTypeInput(typeManager))
				.newLine()
				.text("Pointer")
				.addItem(m_pointerInput = new Elements::Input::Int)
				.newLine()
				.text("Array")
				.addItem(m_arrayInput = new Elements::Input::Int)
				.newLine()
				.newLine()
				.addItem(m_preview = new Elements::Text::Text("select a type"))
				.newLine()
				.newLine()
				.addItem(
					new Elements::Button::ButtonStd("Ok", new Events::EventUI(
						EVENT_LAMBDA(info) {
							sendCloseEvent();
						}
				)));

			m_dataTypeInput->m_selectDataType += m_updateEvent;
			m_pointerInput->getSpecialEvent() += m_updateEvent;
			m_arrayInput->getSpecialEvent() += m_updateEvent;
		}

		~DataTypeSelector() {
			if (m_type != nullptr)
				m_type->free();
		}

		bool checkData() {
			if(!m_dataTypeInput->isTypeSelected())
				return false;
			if (m_pointerInput->getInputValue() < 0 || m_pointerInput->getInputValue() > 10)
				return false;
			if (m_arrayInput->getInputValue() < 0)
				return false;
			return true;
		}

		void onUpdateInput() {
			if (!checkData())
				return;

			if (m_type != nullptr)
				m_type->free();

			m_type = m_typeManager->getType(
				m_dataTypeInput->getSelectedType(),
				m_pointerInput->getInputValue(),
				m_arrayInput->getInputValue()
			);

			updatePreview();
		}

		void updatePreview() {
			m_preview->setText(m_type->getDisplayName());
		}

		void setType(CE::Type::Type* type) {
			m_type = type;
			m_dataTypeInput->setSelectedType(type);
			m_pointerInput->setInputValue(type->getPointerLvl());
			m_arrayInput->setInputValue(type->getArraySize());
			updatePreview();
		}

		CE::Type::Type* getType() {
			return m_type;
		}
	private:
		CE::Type::Type* m_type = nullptr;
		TypeManager* m_typeManager;
		Widget::DataTypeInput* m_dataTypeInput;
		Elements::Input::Int* m_pointerInput;
		Elements::Input::Int* m_arrayInput;
		Events::EventHandler* m_updateEvent;
		Elements::Text::Text* m_preview;
	};
};