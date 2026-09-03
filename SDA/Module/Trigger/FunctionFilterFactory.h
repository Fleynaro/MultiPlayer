#pragma once
#include "Filters/Cmp/ArgumentCmpFilter.h"
#include "Filters/Cmp/ReturnValueArgumentFilter.h"
#include "Filters/ConditionFilter.h"
#include "Filters/OtherFilters.h"

namespace CE
{
	namespace TreeNodeInfo
	{
		struct TreeNode {
			std::string m_name;
			std::string m_desc;

			TreeNode(const std::string& name, const std::string& desc)
				: m_name(name), m_desc(desc)
			{}

			virtual ~TreeNode() {}
		};

		struct Category : public TreeNode {
			std::list<TreeNode*> m_nodes;

			Category(const std::string& name, const std::string& desc, std::list<TreeNode*> nodes = {})
				: TreeNode(name, desc), m_nodes(nodes)
			{}
		};

		template<class T1, typename T2>
		static T1* GetFilter_(T2 id, TreeNode* node) {
			if (T1* filter = dynamic_cast<T1*>(node)) {
				if (filter->m_id == id)
					return filter;
			}
			if (Category* category = dynamic_cast<Category*>(node)) {
				for (auto it : category->m_nodes) {
					if (T1* filter = GetFilter_<T1, T2>(id, it)) {
						return filter;
					}
				}
			}
			return nullptr;
		}
	};

	namespace TriggerFilterInfo
	{
		using namespace TreeNodeInfo;

		namespace Function
		{
			using namespace Trigger::Function::Filter;

			struct Filter : public TreeNode {
				Id m_id;
				std::function<AbstractFilter * ()> m_createFilter;

				Filter(Id id, const std::function<AbstractFilter * ()>& createFilter, const std::string& name, const std::string& desc = "")
					: m_id(id), m_createFilter(createFilter), TreeNode(name, desc)
				{}
			};

			static inline Category* RootCategory =
				new Category("Filters", "", {
					new Category("Condition", "", {
						new Filter(Id::Condition_AND, []() { return new ConditionFilter(Id::Condition_AND); }, "AND"),
						new Filter(Id::Condition_OR, []() { return new ConditionFilter(Id::Condition_OR); }, "OR"),
						new Filter(Id::Condition_XOR, []() { return new ConditionFilter(Id::Condition_XOR); }, "XOR"),
						new Filter(Id::Condition_NOT, []() { return new ConditionFilter(Id::Condition_NOT); }, "NOT")
					}),
					new Filter(Id::Empty, []() { return new Empty; }, "Empty"),
					new Filter(Id::Object, []() { return new Object; }, "Object"),
					new Filter(Id::Argument, []() { return new Cmp::Argument; }, "Argument"),
					new Filter(Id::ReturnValue, []() { return new Cmp::RetValue; }, "Return value")
					});

			static Filter* GetFilter(Id id) {
				return GetFilter_<Filter>(id, RootCategory);
			}
		};
	};
};