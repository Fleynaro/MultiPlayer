#pragma once
#include "UserType.h"
#include "SystemType.h"
#include "../Function/MethodDeclaration.h"
#include "../VTable/VTable.h"

namespace CE::Type
{
	class Class : public UserType
	{
	public:
		class Field
		{
		public:
			Field(const std::string& name, Type* type, std::string desc = "");

			~Field();

			std::string& getName();

			void setName(const std::string& name);

			std::string& getDesc();

			void setType(Type* type);

			Type* getType();
		private:
			std::string m_name;
			std::string m_desc;
			Type* m_type = nullptr;
		};

		using FieldDict = std::map<int, Field*>;
		using MethodList = std::list<Function::MethodDecl*>;
			
		Class(int id, std::string name, std::string desc = "");

		~Class();

		Group getGroup() override;

		int getSize() override;

		int getSizeWithoutVTable();

		int getRelSize();

		void resize(int size);

		MethodList& getMethodList();

		FieldDict& getFieldDict();

		void addMethod(Function::MethodDecl* method);

		int getAllMethodCount();

		int getAllFieldCount();

		int getBaseOffset();

		bool iterateClasses(std::function<bool(Class*)> callback);

	private:
		bool iterateAllMethods(std::function<bool(Function::MethodDecl*)> callback);

	public:
		bool iterateMethods(std::function<bool(Function::MethodDecl*)> callback);

		bool iterateFields(const std::function<bool(int&, Field*)>& callback, bool emptyFields = false);

		bool iterateFields(const std::function<bool(Class*, int&, Field*)>& callback, bool emptyFields = false);

		bool iterateFieldsWithOffset(std::function<bool(Class*, int, Field*)> callback, bool emptyFields = false);

		Class* getBaseClass();

		void setBaseClass(Class* base);

		Function::VTable* getVtable();

		bool hasVTable();

		void setVtable(Function::VTable* vtable);

		int getSizeByLastField();

		std::pair<Class*, int> getFieldLocationByOffset(int offset);

		int getNextEmptyBytesCount(int startByteIdx);

		bool areEmptyFields(int startByteIdx, int size);

		static Field* getDefaultField();

		static bool isDefaultField(Field* field);

		std::pair<int, Field*> getField(int relOffset);

		FieldDict::iterator getFieldIterator(int relOffset);

	private:
		void moveField_(int relOffset, int bytesCount);
	public:
		bool moveField(int relOffset, int bytesCount);

		bool moveFields(int relOffset, int bytesCount);

		void addField(int relOffset, std::string name, Type* type, const std::string& desc = "");

		bool removeField(int relOffset);
	private:
		int m_size = 0;
		Function::VTable* m_vtable = nullptr;
		Class* m_base = nullptr;
		FieldDict m_fields;
		MethodList m_methods;
	};
};