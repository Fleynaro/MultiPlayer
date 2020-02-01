#pragma once
#include "Shared/GUI/Windows/Templates/ItemList.h"
#include "GUI/Type.h"
#include <Manager/FunctionManager.h>

using namespace CE;

namespace GUI::Window
{
	class DataTypeList : public Template::ItemList
	{
	public:
		class TypeFilter : public Filter
		{
		public:
			TypeFilter(const std::string& name, DataTypeList* dataTypeList)
				: Filter(name), m_dataTypeList(dataTypeList)
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

			CategoryFilter(DataTypeList* dataTypeList, const StyleSettings& style)
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
				m_dataTypeList->update();
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

		DataTypeList(TypeManager* typeManager, const StyleSettings& style = StyleSettings())
			: m_typeManager(typeManager), ItemList("Data type list", style)
		{
			addTypeFilter(new CategoryFilter(this, style));
		}

		void addTypeFilter(TypeFilter* filter) {
			addFilter(filter);
			m_typeFiltes.push_back(filter);
		}

		void onSearch(const std::string& value) override
		{
			clear();
			for (auto& it : m_typeManager->getTypes()) {
				if (checkOnInputValue(it.second, value) && checkAllFilters(it.second)) {
					add(new TypeItem(it.second));
				}
			}
		}

		bool checkOnInputValue(API::Type::Type* type, const std::string& value) {
			return Generic::String::ToLower(type->getType()->getName())
				.find(Generic::String::ToLower(value)) != std::string::npos;
		}

		bool checkAllFilters(API::Type::Type* type) {
			for (auto filter : m_typeFiltes) {
				if (filter->isDefined() && !filter->checkFilter(type)) {
					return false;
				}
			}
			return true;
		}
	private:
		TypeManager* m_typeManager;
		std::list<TypeFilter*> m_typeFiltes;
	};
};