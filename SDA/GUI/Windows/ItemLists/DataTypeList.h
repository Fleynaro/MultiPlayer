#pragma once
#include "Shared/GUI/Widgets/Template/ItemList.h"
#include "GUI/Type.h"
#include <Manager/FunctionManager.h>

using namespace CE;

namespace GUI::Widget
{
	class DataTypeList : public Template::ItemList
	{
	public:
		class ListView : public IView
		{
		public:
			class TypeItem : public Item
			{
			public:
				TypeItem(API::Type::Type* type)
				{
					setHeader(type->getType()->getName());
					beginBody()
						.text(GUI::Units::Type::getTooltipDesc(type->getType(), false));
				}
			};

			ListView(DataTypeList* dataTypeList, TypeManager* typeManager)
				: m_dataTypeList(dataTypeList), m_typeManager(typeManager)
			{}

			void onSearch(const std::string& value) override
			{
				m_dataTypeList->getItemsContainer().clear();
				for (auto& it : m_typeManager->getTypes()) {
					if (m_dataTypeList->checkOnInputValue(it.second, value) && m_dataTypeList->checkAllFilters(it.second)) {
						m_dataTypeList->getItemsContainer().addItem(new TypeItem(it.second));
					}
				}
			}
		protected:
			TypeManager* m_typeManager;
			DataTypeList* m_dataTypeList;
		};

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
						->setWidth(dataTypeList->m_styleSettings->m_leftWidth - 10),
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
			: ItemList("Data type list", new TypeFilterCreator(this))
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
	private:
		std::list<TypeFilter*> m_typeFiltes;
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