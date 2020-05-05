#pragma once
#include "Structure.h"
#include "SystemType.h"
#include "../Function/MethodDeclaration.h"
#include "../VTable/VTable.h"
#include <Utils/Iterator.h>

namespace CE::DataType
{
	/*
		Класс - это структура, то есть набор байт в памяти
		Наследование - это структура в структуре
		Полиморфизм - ссылка на виртуальную таблицу в памяти
		Сделать класс на основе структуры
	*/

	class Class : public Structure
	{
	public:
		using MethodListType = std::list<Function::MethodDecl*>;

		class MethodIterator : public IIterator<Function::MethodDecl*>
		{
		public:
			MethodIterator(Class* Class)
				: m_vtable(Class->getVtable())
			{
				m_classes = Class->getClassesInHierarchy();
				updateIterator();
			}

			bool hasNext() override {
				if(!(m_classes.size() != 0 && m_iterator != m_end))
					return false;
				if (m_signatures.count((*m_iterator)->getSigName()) != 0) {
					next();
					return hasNext();
				}
				return true;
			}

			Function::MethodDecl* next() override {
				//vtable...
				
				if (m_iterator == m_end) {
					m_classes.pop_front();
					updateIterator();
				}

				auto method = *m_iterator;
				m_iterator++;
				m_signatures.insert(method->getSigName());
				return method;
			}
		private:
			Function::VTable* m_vtable;
			std::list<Class*> m_classes;
			MethodListType::iterator m_iterator;
			MethodListType::iterator m_end;
			std::set<std::string> m_signatures;

			void updateIterator() {
				m_iterator = m_classes.front()->getMethods().begin();
				m_end = m_classes.front()->getMethods().begin();
			}
		};

		Class(TypeManager* typeManager, const std::string& name, const std::string& desc = "");

		Group getGroup() override;

		MethodListType& getMethods();

		void addMethod(Function::MethodDecl* method);

		std::list<Class*> getClassesInHierarchy();

		Class* getBaseClass();

		void setBaseClass(Class* base);

		Function::VTable* getVtable();

		bool hasVTable();

		void setVtable(Function::VTable* vtable);
	private:
		Function::VTable* m_vtable = nullptr; //просто для галочки, по сути - это массив определенний undefined вирт. функций
		Class* m_base = nullptr;
		MethodListType m_methods;
	};
};