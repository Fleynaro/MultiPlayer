#pragma once
#include "Shared/GUI/Items/IWindow.h"
#include <Manager/TypeManager.h>

using namespace CE;

namespace GUI::Widget
{
	class ClassContent
		: ColContainer
	{
	public:
		class Field
			: public TreeNode
		{
		public:
			Field()

			{}
		};

		class Method
			: public TreeNode
		{
		public:
			Method()

			{}
		};

		ClassContent(Type::Class* Class)
			: ClassContent(Class, Class->getBaseOffset())
		{}

		ClassContent(Type::Class* Class, int baseOffset)
			: m_class(Class), m_baseOffset(baseOffset), ColContainer(Class->getName())
		{
			buildFields();
			buildMethods();
		}

		void buildFields() {
			for (auto& field : getClass()->getFieldDict()) {

			}
		}

		void buildMethods() {
			for (auto method : getClass()->getMethodList()) {
				
			}
		}

		Type::Class* getClass() {
			return m_class;
		}
	private:
		int m_baseOffset;
		Type::Class* m_class;
	};

	class ClassEditor
		: public Container
	{
	public:
		ClassEditor(Type::Class* Class)
			: m_class(Class)
		{
			if (getClass()->hasVTable())
				buildVTable();
			buildContent();
		}
		
		void buildVTable() {
			auto vTable = getClass()->getVtable();

		}

		void buildContent() {

		}

		Type::Class* getClass() {
			return m_class;
		}
	private:
		Type::Class* m_class;
	};
};