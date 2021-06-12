#pragma once
#include "Structure.h"
#include "SystemType.h"
#include "../Function/Function.h"
#include <Utils/Iterator.h>

namespace CE::DataType
{
	/*
		����� - ��� ���������, �� ���� ����� ���� � ������
		������������ - ��� ��������� � ���������
		����������� - ������ �� ����������� ������� � ������
		������� ����� �� ������ ���������
	*/

	class Class : public Structure
	{
	public:
		using MethodListType = std::list<Function::Function*>;

		class MethodIterator : public IIterator<Function::Function*>
		{
		public:
			MethodIterator(Class* Class);

			bool hasNext() override;

			Function::Function* next() override;
		private:
			std::list<Class*> m_classes;
			MethodListType::iterator m_iterator;
			MethodListType::iterator m_end;
			std::set<std::string> m_signatures;

			void updateIterator();
		};

		Class(TypeManager* typeManager, const std::string& name, const std::string& comment = "")
			: Structure(typeManager, name, comment)
		{}

		Group getGroup() override;

		MethodListType& getMethods();

		void addMethod(Function::Function* method);

		std::list<Class*> getClassesInHierarchy();

		Class* getBaseClass();

		void setBaseClass(Class* base, bool createBaseClassField = true);
	private:
		Class* m_base = nullptr;
		MethodListType m_methods;
	};
};