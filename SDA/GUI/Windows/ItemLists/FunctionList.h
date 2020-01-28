#pragma once
#include "Shared/GUI/Windows/Templates/ItemList.h"
#include "GUI/Signature.h"
#include <Manager/FunctionManager.h>

using namespace CE;

namespace GUI::Window
{
	class FunctionList : public Template::ItemList
	{
	public:
		class FunctionFilter : public Filter
		{
		public:
			FunctionFilter(const std::string& name)
				: Filter(name)
			{}

			virtual bool checkFilter(API::Function::Function* function) = 0;
		};

		class ClassFilter : public FunctionFilter
		{
		public:
			ClassFilter()
				: FunctionFilter("Class filter")
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

		class FunctionItem : public Item
		{
		public:
			FunctionItem(API::Function::Function* function)
			{
				setHeader(function->getFunction()->getSigName());
				beginBody()
					.addItem(
						new Units::Signature(function,
							new Events::EventUI(EVENT_LAMBDA(info) {
								
							}),
							new Events::EventUI(EVENT_LAMBDA(info) {

							}),
							new Events::EventUI(EVENT_LAMBDA(info) {
								auto argId = m_signautre->m_argumentSelectedIdx;

							})
						),
						(GUI::Item**)& m_signautre
					)
					.newLine()
					.newLine();
			}

		private:
			Units::Signature* m_signautre;
		};

		FunctionList(FunctionManager* funcManager, const StyleSettings& style = StyleSettings())
			: m_funcManager(funcManager), ItemList("Function list", style)
		{
			addFunctionFilter(new ClassFilter);
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
					add(new FunctionItem(it.second));
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
	private:
		FunctionManager* m_funcManager;
		std::list<FunctionFilter*> m_funcFiltes;
	};
};