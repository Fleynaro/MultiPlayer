#pragma once

#include "Template/CategoryListSearch.h"
#include "Core/ScriptLang/ClassBuilder.h"
#include "TypeView.h"

namespace GUI::Widget
{
	class SdkClassListSearch : public Template::CategoryListSearch
	{
	public:
		class Printer
		{
		public:
			Printer(SdkClassListSearch* parent)
				: m_parent(parent)
			{}

			Item* buildEnum(Class::Builder* Class, Class::Enum* enumClass)
			{
				auto item = new Item(new TreeNode("<enum> " + enumClass->getName(), false));
				auto container = item->getContainer<TreeNode>();

				std::list<std::string> keywords = {
					String::ToLower(enumClass->getName())
				};

				for (auto it : enumClass->getItems()) {
					(*container)
						.addItem(
							new TypeView::TextToCopy(
								it.first,
								ColorRGBA(0xCCE9A4ff),
								m_parent->m_clickTextToCopy
							)
						)
						.sameLine(0.f).text(" = " + std::to_string(it.second))
						.sameLine(0.f).text(",");

					keywords.push_back(String::ToLower(it.first));
				}
				container->getItems().pop_back();
				container->getItems().pop_back();

				item->setKeywordList(keywords);
				return item;
			}

			Item* buildAccessor(Class::Builder* Class, Class::Accessor* accessor)
			{
				auto item = new Item(new TreeNode("", false));
				auto container = item->getContainer<TreeNode>();
				std::string name = accessor->getName() + " ";

				if (accessor->m_lua_call_accessor_get != nullptr) {
					(*container)
						.addItem(
							new TypeView::TypeText(
								TypeView::getTypeByRawType(accessor->getType()).release(),
								m_parent->m_clickTypeText
							)
						)
						.text(" value = ").sameLine(0.f)
						.addItem(
							new TypeView::TextToCopy(
								accessor->getName(),
								ColorRGBA(-1),
								m_parent->m_clickTextToCopy
							)
						);

					name += "<getter> ";
				}

				if (accessor->m_lua_call_accessor_set != nullptr) {
					(*container)
						.addItem(
							new TypeView::TextToCopy(
								accessor->getName(),
								ColorRGBA(-1),
								m_parent->m_clickTextToCopy
							)
						)
						.sameLine(0.f).text(" = ").sameLine(0.f)
						.addItem(
							new TypeView::TypeText(
								TypeView::getTypeByRawType(accessor->getType()).release(),
								m_parent->m_clickTypeText
							)
						)
						.text(" value");

					name += "<setter>";
				}

				container->setName(name);
				item->setKeywordList({ String::ToLower(accessor->getName()) });
				return item;
			}

			Item* buildMethod(Class::Builder* Class, Class::Method* method)
			{
				auto item = new Item(new TreeNode("", false));
				auto container = item->getContainer<TreeNode>();
				std::string name;

				{
					//returned value
					auto retType
						= TypeView::getTypeByRawType(method->getType()).release();
					(*container)
						.separator()
						.addItem(
							new TypeView::TypeText(
								retType,
								m_parent->m_clickTypeText
							)
						)
						.text(" ").sameLine(0.f)
						.addItem(
							new TypeView::TextToCopy(
								method->getName(),
								ColorRGBA(-1),
								m_parent->m_clickTextToCopy
							)
						)
						.sameLine(0.f).text("(");

					//-- title name --
					name += retType->getName() + " " + method->getName() + "(";
				}

				//argument list
				int idx = 0;
				for (auto arg : method->getArgInfo()) {
					auto argType
						= TypeView::getTypeByRawType(arg.m_typeName).release();
					(*container)
						.sameLine(0.f)
						.addItem(
							new TypeView::TypeText(
								argType,
								m_parent->m_clickTypeText
							)
						)
						.text(" " + arg.m_name, ColorRGBA(0xCBCBCBFF)).sameLine(0.f);
					
					//-- title name --
					name += argType->getName() + " " + arg.m_name;


					//default value
					if (arg.m_defaultValue != Class::Method::anyValue)
					{
						auto defVal = TypeView::getDefaultValue(argType, arg.m_defaultValue);
						(*container)
							.text("=" + defVal, ColorRGBA(0x8E8E8EFF)).sameLine(0.f);

						//-- title name --
						name += "=" + defVal;
					}


					(*container)
						.text(", ");

					//-- title name --
					name += ", ";
					idx++;
				}
				if(idx) container->getItems().pop_back();
				(*container)
					.text(")");

				//title name
				{
					if (idx) {
						name.pop_back();
						name.pop_back();
					}
					container->setName(name + ")");
				}
				item->setKeywordList({ String::ToLower(method->getName()) });
				return item;
			}

			Item* buildStaticMethod(Class::Builder* Class, Class::StaticMethod* stMethod)
			{
				auto method = buildMethod(Class, stMethod);
				method->getContainer<TreeNode>()->setName("<static> " + method->getContainer<TreeNode>()->getName());
				return method;
			}

			Item* buildConstructor(Class::Builder* Class, Class::Constructor* constructor)
			{
				auto method = buildMethod(Class, constructor);
				method->getContainer<TreeNode>()->setName("<constructor> " + method->getContainer<TreeNode>()->getName());
				return method;
			}
		private:
			SdkClassListSearch* m_parent;
		};

		SdkClassListSearch()
			: m_printer(new Printer(this))
		{
			m_clickTypeText = new Events::EventUI(
				EVENT_METHOD_PASS(clickTypeText)
			);
			m_clickTypeText->setCanBeRemoved(false);

			m_clickTextToCopy = new Events::EventUI(
				EVENT_METHOD_PASS(clickTextToCopy)
			);
			m_clickTextToCopy->setCanBeRemoved(false);

			for (auto Class : Class::Environment::getClasses()) {
				std::string name = Class->getName();
				if (Class->getParent() != nullptr) {
					name += " <base class = "+ Class->getParent()->getName() +">";
				}

				auto& category = beginCategory(name);
				buildCategory(category, Class);
				category.m_externalPtr = Class;
			}
			showAll();
		}
		~SdkClassListSearch() {
			delete m_printer;
			delete m_clickTextToCopy;
			delete m_clickTypeText;
		}

		void buildCategory(Category& cat, Class::Builder* Class)
		{
			if (Class->getConstructor() != nullptr) {
				cat.addItem(
					m_printer->buildConstructor(Class, Class->getConstructor())
				);
			}

			for (auto member : Class->getMembers()) {
				if (!member->isEnum())
					continue;
				cat.addItem(
					m_printer->buildEnum(Class, (Class::Enum*)member)
				);
			}

			for (auto member : Class->getMembers()) {
				if (!member->isAccessor())
					continue;
				cat.addItem(
					m_printer->buildAccessor(Class, (Class::Accessor*)member)
				);
			}

			for (auto member : Class->getMembers()) {
				if (!member->isMethod())
					continue;
				cat.addItem(
					m_printer->buildMethod(Class, (Class::Method*)member)
				);
			}

			for (auto member : Class->getMembers()) {
				if (!member->isStaticMethod())
					continue;
				cat.addItem(
					m_printer->buildStaticMethod(Class, (Class::StaticMethod*)member)
				);
			}
		}

		Events::EventUI* m_clickTextToCopy = nullptr;
		EVENT_METHOD(clickTextToCopy, info)
		{
			auto sender = (TypeView::TextToCopy*)info->getSender();
			ImGui::SetClipboardText(sender->getText().c_str());
		}

		Events::EventUI* m_clickTypeText = nullptr;
		EVENT_METHOD(clickTypeText, info)
		{
			auto sender = (TypeView::TypeText*)info->getSender();
			auto typeId = sender->getType()->getId();
			if (typeId == TypeView::Type::Class || typeId == TypeView::Type::Enum) {
				auto Class = ((TypeView::ClassType*)sender->getType())->getBuilder();
				if (Class != nullptr)
				{
					auto cat = getCategoryByExPtr(Class);
					if (cat != nullptr)
					{
						updateOnInputValue("");
						hideAllCategories();
						showCategory(cat);
						m_retBackBtn->setDisplay(true);
					}
				}
			}
		}
	private:
		Printer* m_printer;
	};
};