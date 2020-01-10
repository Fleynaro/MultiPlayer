#pragma once

#include <main.h>
#include <DynHook/DynHook.h>
#include <SQLiteCpp/SQLiteCpp.h>
#include <Utility/FileWrapper.h>

void module_sda();



#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/protocol/TMultiplexedProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>
#include "DataTypeManagerService.h"
#include "FunctionManagerService.h"
using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;



namespace CE
{
	class IDesc
	{
	public:
		virtual int getId() = 0;
		virtual std::string getName() = 0;
		virtual std::string getDesc() {
			return "Not desc.";
		}
	};

	class Desc : public IDesc
	{
	public:
		Desc(int id, std::string name, std::string desc = "")
			: m_id(id), m_name(name), m_desc(desc)
		{}

		int getId() override {
			return m_id;
		}

		std::string getName() override {
			return m_name;
		}

		std::string getDesc() override {
			return m_desc;
		}

		void setName(const std::string& name) {
			m_name = name;
		}

		void setDesc(const std::string& desc) {
			m_desc = desc;
		}
	protected:
		int m_id;
		std::string m_name;
		std::string m_desc;
	};

	class IGhidraUnit
	{
	public:
		virtual bool isGhidraUnit() = 0;
		virtual void setGhidraUnit(bool toggle) = 0;
	};

	namespace Type
	{
		class Type : public IDesc
		{
		public:
			enum Group
			{
				Simple,
				Enum,
				Class,
				Typedef,
				Signature
			};

			virtual Group getGroup() = 0;
			virtual std::string getDisplayName() = 0;
			virtual int getPointerLvl() = 0;
			virtual int getArraySize() = 0;
			virtual int getSize() = 0;
			virtual bool isUserDefined() = 0;
			virtual void free() {}

			bool isSystem() {
				return !isUserDefined();
			}

			bool isPointer() {
				return getPointerLvl() != 0;
			}

			bool isArray() {
				return getArraySize() != 0;
			}

			bool isArrayOfPointers() {
				return isArray() && isPointer();
			}
		};

		class UserType : public Type, public IGhidraUnit
		{
		public:
			UserType(int id, std::string name, std::string desc = "")
				: m_id(id), m_name(name), m_desc(desc)
			{}

			bool isUserDefined() override {
				return true;
			}

			int getPointerLvl() override {
				return 0;
			}

			int getArraySize() override {
				return 0;
			}

			int getId() override {
				return m_id;
			}

			std::string getDisplayName() override {
				return getName();
			}

			std::string getName() override {
				return m_name;
			}

			std::string getDesc() override {
				return m_desc;
			}

			void setName(const std::string& name) {
				m_name = name;
			}

			void setDesc(const std::string& desc) {
				m_desc = desc;
			}

			bool isGhidraUnit() override {
				return m_ghidraUnit;
			}

			void setGhidraUnit(bool toggle) override {
				m_ghidraUnit = toggle;
			}
		private:
			int m_id;
			std::string m_name;
			std::string m_desc;
			bool m_ghidraUnit = true;
			
		};

		class SystemType : public Type
		{
		public:
			enum Set
			{
				Undefined,
				Boolean,
				Integer,
				Real
			};

			enum Types : int
			{
				Void = 1,
				Bool,
				Byte,
				Int8,
				Int16,
				Int32,
				Int64,
				UInt16,
				UInt32,
				UInt64,
				Float,
				Double
			};

			virtual Set getSet() = 0;

			Group getGroup() override {
				return Group::Simple;
			}

			std::string getDisplayName() override {
				return getName();
			}

			bool isUserDefined() override {
				return false;
			}

			int getPointerLvl() override {
				return 0;
			}

			int getArraySize() override {
				return 0;
			}

			static Types GetBasicTypeOf(Type* type);
			static Set GetNumberSetOf(Type* type);
		};

		class Typedef : public UserType
		{
		public:
			Typedef(Type* refType, int id, std::string name, std::string desc = "")
				: UserType(id, name, desc)
			{
				setRefType(refType);
			}

			Group getGroup() override {
				return Group::Typedef;
			}

			int getSize() override {
				if (getRefType() == this)
					return 0;
				return getRefType()->getSize();
			}

			void setRefType(Type* refType) {
				m_refType = refType;
			}

			Type* getRefType() {
				return m_refType;
			}
		private:
			Type* m_refType = nullptr;
		};

		class Void : public SystemType
		{
		public:
			int getId() override {
				return SystemType::Void;
			}

			std::string getName() override {
				return "void";
			}

			std::string getDesc() override {
				return "void is a special return type for functions only";
			}

			Set getSet() {
				return Set::Undefined;
			}

			int getSize() override {
				return 0;
			}
		};

		class Bool : public SystemType
		{
		public:
			int getId() override {
				return SystemType::Bool;
			}

			std::string getName() override {
				return "bool";
			}

			std::string getDesc() override {
				return "bool is a byte type";
			}

			Set getSet() {
				return Set::Boolean;
			}

			int getSize() override {
				return 1;
			}
		};

		class Byte : public SystemType
		{
		public:
			int getId() override {
				return SystemType::Byte;
			}

			std::string getName() override {
				return "byte";
			}

			std::string getDesc() override {
				return "byte is a byte type";
			}

			Set getSet() {
				return Set::Integer;
			}

			int getSize() override {
				return 1;
			}
		};

		class Int8 : public SystemType
		{
		public:
			int getId() override {
				return SystemType::Int8;
			}

			std::string getName() override {
				return "int8_t";
			}

			std::string getDesc() override {
				return "int8_t is a byte type";
			}

			Set getSet() {
				return Set::Integer;
			}

			int getSize() override {
				return 1;
			}
		};

		class Int16 : public SystemType
		{
		public:
			int getId() override {
				return SystemType::Int16;
			}

			std::string getName() override {
				return "int16_t";
			}

			std::string getDesc() override {
				return "int16_t is 2 byte type";
			}

			Set getSet() {
				return Set::Integer;
			}

			int getSize() override {
				return 2;
			}
		};

		class Int32 : public SystemType
		{
		public:
			int getId() override {
				return SystemType::Int32;
			}

			std::string getName() override {
				return "int32_t";
			}

			std::string getDesc() override {
				return "int32_t is 4 byte type";
			}

			Set getSet() {
				return Set::Integer;
			}

			int getSize() override {
				return 4;
			}
		};

		class Int64 : public SystemType
		{
		public:
			int getId() override {
				return SystemType::Int64;
			}

			std::string getName() override {
				return "int64_t";
			}

			std::string getDesc() override {
				return "int64_t is 8 byte type";
			}

			Set getSet() {
				return Set::Integer;
			}

			int getSize() override {
				return 8;
			}
		};

		class UInt16 : public SystemType
		{
		public:
			int getId() override {
				return SystemType::UInt16;
			}

			std::string getName() override {
				return "uint16_t";
			}

			std::string getDesc() override {
				return "int16_t is 2 byte unsigned type";
			}

			Set getSet() {
				return Set::Integer;
			}

			int getSize() override {
				return 2;
			}
		};

		class UInt32 : public SystemType
		{
		public:
			int getId() override {
				return SystemType::UInt32;
			}

			std::string getName() override {
				return "uint32_t";
			}

			std::string getDesc() override {
				return "int32_t is 4 byte unsigned type";
			}

			Set getSet() {
				return Set::Integer;
			}

			int getSize() override {
				return 4;
			}
		};

		class UInt64 : public SystemType
		{
		public:
			int getId() override {
				return SystemType::UInt64;
			}

			std::string getName() override {
				return "uint64_t";
			}

			std::string getDesc() override {
				return "int64_t is 8 byte unsigned type";
			}

			Set getSet() {
				return Set::Integer;
			}

			int getSize() override {
				return 8;
			}
		};

		class UInt128 : public SystemType
		{
		public:
			int getId() override {
				return SystemType::UInt64;
			}

			std::string getName() override {
				return "uint128_t";
			}

			std::string getDesc() override {
				return "int128_t is 16 byte unsigned type";
			}

			Set getSet() {
				return Set::Integer;
			}

			int getSize() override {
				return 16;
			}
		};

		class Float : public SystemType
		{
		public:
			int getId() override {
				return SystemType::Float;
			}

			std::string getName() override {
				return "float";
			}

			std::string getDesc() override {
				return "float is 4 byte type";
			}

			Set getSet() {
				return Set::Real;
			}

			int getSize() override {
				return 4;
			}
		};

		class Double : public SystemType
		{
		public:
			int getId() override {
				return SystemType::Double;
			}

			std::string getName() override {
				return "double";
			}

			std::string getDesc() override {
				return "double is 8 byte type";
			}

			Set getSet() {
				return Set::Real;
			}

			int getSize() override {
				return 8;
			}
		};

		class Pointer : public Type
		{
		public:
			Pointer(Type* type)
				: m_type(type)
			{}

			void free() override {
				getType()->free();
				delete this;
			}

			Group getGroup() override {
				return getType()->getGroup();
			}

			bool isUserDefined() override {
				return getType()->isUserDefined();
			}

			int getId() override {
				return getType()->getId();
			}

			std::string getName() override {
				return getType()->getName();
			}

			std::string getDisplayName() override {
				return getType()->getName() + "*";
			}

			int getSize() override {
				return 8;
			}

			Type* getType() {
				return m_type;
			}

			int getPointerLvl() override {
				return getType()->getPointerLvl() + 1;
			}

			int getArraySize() override {
				return 0;
			}
		private:
			Type* m_type;
		};

		class Array : public Pointer
		{
		public:
			Array(Type* type, uint64_t arraySize)
				: Pointer(type), m_arraySize(arraySize)
			{}

			void free() override {
				getType()->free();
				delete this;
			}

			Group getGroup() override {
				return getType()->getGroup();
			}

			std::string getName() override {
				return getType()->getName();
			}

			std::string getDisplayName() override {
				return getType()->getName() + "[" + std::to_string(getArraySize()) + "]";
			}

			int getSize() override {
				return getArraySize() * getType()->getSize();
			}

			int getPointerLvl() override {
				return getType()->getPointerLvl();
			}

			int getArraySize() override {
				return m_arraySize;
			}
		private:
			uint64_t m_arraySize;
		};

		class Class;
	};

	namespace Variable
	{
		class Variable
		{
		public:
			Variable(Type::Type* type)
				: m_type(type)
			{}

			Type::Type* getType() {
				return m_type;
			}
		private:
			Type::Type* m_type;
		};

		class Global : public Variable, public Desc
		{
		public:
			Global(Type::Type* type, void* addr, int id, std::string name, std::string desc = "")
				: Variable(type), m_addr(addr), Desc(id, name, desc)
			{}

			void* getAddress() {
				return m_addr;
			}
		private:
			void* m_addr;
		};

		class Local : public Variable
		{
		public:
			Local(Type::Type* type, void* addr)
				: Variable(type), m_addr(addr)
			{}

			
		private:
			void* m_addr;
		};

		class Param : public Local
		{
		public:
			
		};
	};

	namespace CallGraph
	{
		class FunctionBody;
	};

	namespace Trigger
	{
		namespace Function {
			class Hook;
		};
	};

	namespace Function
	{
		class Signature
		{
		public:
			using ArgTypeList = std::vector<Type::Type*>;

			Signature() {}

			void setReturnType(Type::Type* returnType) {
				m_returnType = returnType;
				//m_retTypeChanged = true;
			}

			Type::Type* getReturnType() {
				return m_returnType;
			}

			ArgTypeList& getArgList() {
				return m_args;
			}

			//bool m_retTypeChanged = false;
		private:
			ArgTypeList m_args;
			Type::Type* m_returnType = nullptr;
		};

		class Method;
		class Function : public Desc, public IGhidraUnit
		{
		public:
			using ArgList = std::vector<Variable::Param>;
			using ArgNameList = std::vector<std::string>;

			class Range
			{
			public:
				Range() = default;
				Range(void* min_addr, void* max_addr)
					: m_min_addr(min_addr), m_max_addr(max_addr)
				{}
				Range(void* entry_addr, int size)
					: m_min_addr(entry_addr), m_max_addr((void*)((std::uintptr_t)entry_addr + size))
				{}

				bool isContainingAddress(void* addr) {
					return (std::uintptr_t)addr >= (std::uintptr_t)getMinAddress() && (std::uintptr_t)addr <= (std::uintptr_t)getMaxAddress();
				}

				std::uintptr_t getSize() {
					return (std::uintptr_t)getMaxAddress() - (std::uintptr_t)getMinAddress();
				}

				void* getMinAddress() {
					return m_min_addr;
				}

				void* getMaxAddress() {
					return m_max_addr;
				}
			private:
				void* m_min_addr = nullptr;
				void* m_max_addr = nullptr;
			};

			using RangeList = std::vector<Range>;

			Function(void* addr, RangeList ranges, int id, std::string name, std::string desc = "")
				: m_addr(addr), m_ranges(ranges), Desc(id, name, desc)
			{}

			virtual std::string getSigName() {
				std::string name = getSignature().getReturnType()->getName() + " " + getName() + "(";

				auto& argList = getSignature().getArgList();
				for (int i = 0; i < argList.size(); i ++) {
					name += argList[i]->getName() + " " + getArgNameList()[i] + ", ";
				}
				if (argList.size() > 0) {
					name.pop_back();
					name.pop_back();
				}
				return name + ")";
			}

			inline Signature& getSignature() {
				return m_signature;
			}

			virtual bool isMethod() {
				return false;
			}

			virtual void call(ArgList args) {}

			void* getAddress() {
				return m_addr;
			}

			RangeList& getRangeList() {
				return m_ranges;
			}

			CallGraph::FunctionBody* getBody() {
				return m_funcBody;
			}

			void setBody(CallGraph::FunctionBody* body) {
				m_funcBody = body;
			}

			inline ArgNameList& getArgNameList() {
				return m_argNames;
			}

			void addRange(Range range) {
				m_ranges.push_back(range);
			}

			bool isContainingAddress(void* addr) {
				for (auto& range : m_ranges) {
					if (range.isContainingAddress(addr)) {
						return true;
					}
				}
				return false;
			}

			void addArgument(Type::Type* type, std::string name) {
				getSignature().getArgList().push_back(type);
				getArgNameList().push_back(name);
				m_argumentsChanged = true;
			}

			void changeArgument(int id, Type::Type* type, std::string name = "") {
				getSignature().getArgList()[id]->free();
				getSignature().getArgList()[id] = type;
				if (name.length() > 0) {
					m_argNames[id] = name;
				}
				m_argumentsChanged = true;
			}

			void removeLastArgument() {
				getSignature().getArgList().pop_back();
				m_argNames.pop_back();
				m_argumentsChanged = true;
			}
			
			void deleteAllArguments() {
				getSignature().getArgList().clear();
				getArgNameList().clear();
			}

			Method* getMethodBasedOn();

			inline Trigger::Function::Hook* getHook() {
				return m_hook;
			}

			Trigger::Function::Hook* createHook();

			bool m_argumentsChanged = false;

			bool isGhidraUnit() override {
				return m_ghidraUnit;
			}

			void setGhidraUnit(bool toggle) override {
				m_ghidraUnit = toggle;
			}
		protected:
			void* m_addr;
			RangeList m_ranges;
			Signature m_signature;
			ArgNameList m_argNames;
			Trigger::Function::Hook* m_hook = nullptr;
			CallGraph::FunctionBody* m_funcBody = nullptr;
			bool m_ghidraUnit = true;
		};

		class Method : public Function
		{
		public:
			Method(void* addr, RangeList size, int id, std::string name, std::string desc = "")
				: Function(addr, size, id, name, desc)
			{}

			bool isMethod() override {
				return true;
			}

			virtual void call(ArgList args) {}

			std::string getSigName() override {
				return (isVirtual() ? "virtual " : "") + Function::getSigName();
			}

			std::string getName() override;

			void setClass(Type::Class* Class);

			Type::Class* getClass() {
				return (Type::Class*)(((Type::Pointer*)getSignature().getArgList()[0])->getType());
			}

			bool isConstructor() {
				return m_virtual;
			}

			bool isVirtual() {
				return m_virtual;
			}

			Function* getFunctionBasedOn() {
				auto func = new Function(m_addr, m_ranges, getId(), getName(), getDesc());
				func->getArgNameList().swap(getArgNameList());
				func->getSignature().getArgList().swap(getSignature().getArgList());
				func->getSignature().setReturnType(getSignature().getReturnType());
				return func;
			}
		private:
			bool m_constructor = false;
			bool m_virtual = false;
		};

		class VTable : public Desc
		{
		public:
			using vMethodList = std::vector<Method*>;

			VTable(void* addr, int id, std::string name, std::string desc = "")
				: m_addr(addr), Desc(id, name, desc)
			{}

			inline vMethodList& getVMethodList() {
				return m_vmethods;
			}

			void addMethod(Method* method) {
				getVMethodList().push_back(method);
			}

			void* getAddress() {
				return m_addr;
			}
		private:
			void* m_addr;
			vMethodList m_vmethods;
		};
	};

	namespace CallGraph
	{
		enum class Type
		{
			Function = 1,
			GlobalVar,
			NodeGroup = 11,
			Cycle,
			Condition,
			FunctionBody
		};

		class NodeGroup;
		class Node
		{
		public:
			Node() = default;

			virtual Type getGroup() = 0;

			NodeGroup* getParent() {
				return m_parent;
			}

			void setParent(NodeGroup* parent) {
				m_parent = parent;
			}
		private:
			NodeGroup* m_parent = nullptr;
		};

		class NodeGroup : public Node
		{
		public:
			using nodeList = std::vector<Node*>;
			NodeGroup() = default;

			Type getGroup() override {
				return Type::NodeGroup;
			}

			nodeList& getNodeList() {
				return m_nodes;
			}

			void addNode(Node* node) {
				getNodeList().push_back(node);
				node->setParent(this);
			}
		private:
			nodeList m_nodes;
		};

		class FunctionNode : public Node
		{
		public:
			FunctionNode(Function::Function* function)
				: m_function(function)
			{}

			Type getGroup() override {
				return Type::Function;
			}

			Function::Function* getFunction() {
				return m_function;
			}
		private:
			Function::Function* m_function;
		};

		class GlobalVarNode : public Node
		{
		public:
			enum Use {
				Read,
				Write
			};

			GlobalVarNode(Variable::Global* gVar, Use use)
				: m_gVar(gVar), m_use(use)
			{}

			Type getGroup() override {
				return Type::GlobalVar;
			}

			Variable::Global* getGVar() {
				return m_gVar;
			}

			Use getUse() {
				return m_use;
			}
		private:
			Variable::Global* m_gVar;
			Use m_use;
		};

		class Condition : public NodeGroup
		{
		public:
			Condition() = default;

			Type getGroup() override {
				return Type::Condition;
			}
		};

		class Cycle : public NodeGroup
		{
		public:
			Cycle() = default;

			Type getGroup() override {
				return Type::Cycle;
			}
		};

		class FunctionBody : public NodeGroup
		{
		public:
			FunctionBody() = default;

			Type getGroup() override {
				return Type::FunctionBody;
			}
		};

		/*static Node* createGroupNode(Type type)
		{
			switch (type)
			{
			case Type::NodeGroup:
				return new NodeGroup;
			}
		}*/
	};

	namespace Type
	{
		class Enum : public UserType
		{
		public:
			using FieldDict = std::map<int, std::string>;

			Enum(int id, std::string name, std::string desc = "")
				: UserType(id, name, desc)
			{}

			int getSize() override {
				return m_size;
			}

			void setSize(int size) {
				m_size = size;
			}

			Group getGroup() override {
				return Group::Enum;
			}

			FieldDict& getFieldDict() {
				return m_fields;
			}

			bool removeField(int value) {
				auto it = m_fields.find(value);
				if (it != m_fields.end()) {
					m_fields.erase(it);
					return true;
				}
				return false;
			}

			void addField(std::string name, int value) {
				m_fields[value] = name;
			}

			void deleteAll() {
				m_fields.clear();
			}
		private:
			FieldDict m_fields;
			int m_size = 4;
		};

		class Class : public UserType
		{
		public:
			class Field
			{
			public:
				Field(std::string name, Type* type, std::string desc = "")
					: m_name(name), m_type(type), m_desc(desc)
				{}

				std::string& getName() {
					return m_name;
				}

				std::string& getDesc() {
					return m_desc;
				}

				void setType(Type* type) {
					m_type = type;
				}

				inline Type* getType() {
					return m_type;
				}
			private:
				std::string m_name;
				std::string m_desc;
				Type* m_type;
			};

			using FieldDict = std::map<int, Field>;
			using MethodList = std::list<Function::Method*>;

			Class(int id, std::string name, std::string desc = "")
				: UserType(id, name, desc)
			{}

			Group getGroup() override {
				return Group::Class;
			}
		public:
			int getSize() override {
				return getSizeWithoutVTable() + hasVTable() * 0x8;
			}

			int getSizeWithoutVTable() {
				int result = 0;
				if (getBaseClass() != nullptr) {
					result += getBaseClass()->getSizeWithoutVTable();
				}
				return result + getRelSize();
			}

			int getRelSize() {
				return m_size;
			}

			void resize(int size) {
				m_size = size;
			}

			MethodList& getMethodList() {
				return m_methods;
			}

			FieldDict& getFieldDict() {
				return m_fields;
			}

			void addMethod(Function::Method* method) {
				getMethodList().push_back(method);
				method->setClass(this);
			}

			void iterateClasses(std::function<void(Class*)> callback)
			{
				if (getBaseClass() != nullptr) {
					getBaseClass()->iterateClasses(callback);
				}

				callback(this);
			}

			void iterateAllMethods(std::function<void(Function::Method*)> callback)
			{
				for (auto method : getMethodList()) {
					callback(method);
				}

				if (getBaseClass() != nullptr) {
					getBaseClass()->iterateAllMethods(callback);
				}
			}

			void iterateMethods(void(*callback)(Function::Method*))
			{
				std::set<std::string> methods;
				iterateAllMethods([&](Function::Method* method) {
					std::string sigName = method->getSigName();
					if (!methods.count(sigName)) {
						callback(method);
					}
					methods.insert(sigName);
				});
			}

			void iterateFields(std::function<void(Class*, int, Field*)> callback)
			{
				if (getBaseClass() != nullptr) {
					getBaseClass()->iterateFields(callback);
				}

				for (auto& it : m_fields) {
					callback(this, it.first, &it.second);
				}
			}

			void iterateFieldsWithOffset(std::function<void(Class*, int, Field*)> callback)
			{
				int curClassBase = hasVTable() * 0x8;
				Class* curClass = nullptr;
				iterateFields([&](Class* Class, int relOffset, Field* field) {
					if (curClass != nullptr && curClass != Class) {
						curClassBase += curClass->getRelSize();
					}
					int curOffset = curClassBase + relOffset;
					callback(Class, curOffset, field);
				});
			}

			Class* getBaseClass() {
				return m_base;
			}

			void setBaseClass(Class* base) {
				m_base = base;
			}

			Function::VTable* getVtable() {
				if (m_vtable != nullptr && getBaseClass() != nullptr) {
					return getBaseClass()->getVtable();
				}
				return m_vtable;
			}

			bool hasVTable() {
				return getVtable() != nullptr;
			}

			void setVtable(Function::VTable* vtable) {
				m_vtable = vtable;
			}

			std::pair<Class*, int> getFieldLocationByOffset(int offset) {
				std::pair<Class*, int> result(nullptr, -1);
				int curOffset = hasVTable() * 0x8;
				iterateClasses([&](Class* Class) {
					if (curOffset + Class->getRelSize() > offset) {
						if (result.second == -1) {
							result.first = Class;
							result.second = offset - curOffset;
						}
					}
					curOffset += Class->getRelSize();
				});
				return result;
			}

			std::pair<int, Field*> getField(int relOffset) {
				auto it = getFieldIterator(relOffset);
				if (it != m_fields.end()) {
					return std::make_pair(it->first, &it->second);
				}
				static Field defaultField = Field("undefined", new Byte);
				return std::make_pair(-1, &defaultField);
			}

			FieldDict::iterator getFieldIterator(int relOffset) {
				auto it = m_fields.lower_bound(relOffset);
				if (it != m_fields.end()) {
					if (it->first + it->second.getType()->getSize() >= relOffset) {
						return it;
					}
				}
				return m_fields.end();
			}

			bool canTypeBeInsertedTo(int relOffset, int size) {
				if (relOffset + size > getRelSize())
					return false;

				auto field_down = m_fields.lower_bound(relOffset);
				if (field_down != m_fields.end() && field_down->first + field_down->second.getType()->getSize() >= relOffset)
					return false;

				auto field_up = m_fields.upper_bound(relOffset);
				if (field_up != m_fields.end() && field_up->first <= relOffset + size)
					return false;
			}

			void addField(int relOffset, std::string name, Type* type, std::string desc = "") {
				m_fields.insert(std::make_pair(relOffset, Field(name, type, desc)));
				m_size = max(m_size, relOffset + type->getSize());
			}

			bool removeField(int relOffset) {
				auto it = getFieldIterator(relOffset);
				if (it != m_fields.end()) {
					m_fields.erase(it);
					return true;
				}
				return false;
			}
		private:
			int m_size = 0;
			Function::VTable* m_vtable = nullptr;
			Class* m_base = nullptr;
			FieldDict m_fields;
			MethodList m_methods;
		};
	};


	namespace Utils
	{
		class ObjectHash
		{
		public:
			using Hash = int64_t;

			ObjectHash(Hash hash = 0L, std::string hashContent = "")
				: m_hash(hash), m_hashContent(hashContent)
			{}

			void addValue(std::string value) {
				m_hashContent += "{" + value + "}";
			}

			void addValue(int value) {
				addValue((int64_t)value);
			}

			void addValue(int64_t value) {
				addValue(std::to_string(value));
			}

			Hash getHash() {
				return m_hash * 31 + hash(m_hashContent);
			}

			void join(ObjectHash& hash) {
				m_hash = m_hash * 31 + hash.getHash();
			}

			void add(ObjectHash& hash) {
				m_hash = m_hash + hash.getHash();
			}

			static Hash hash(std::string string) {
				Hash h = 1125899906842597L;
				for (int i = 0; i < string.length(); i++) {
					h = 31 * h + string.at(i);
				}
				return h;
			}
		private:
			std::string m_hashContent;
			Hash m_hash;
		};

		class BitStream
		{
		public:
			BitStream() {
				m_bytes.push_back(0);
			}
			BitStream(BYTE* data, int size) {
				setData(data, size);
			}

			void writeBit(bool bit)
			{
				m_bytes[m_curByte] = m_bytes[m_curByte] & ~(0b1 << m_curBit) | (bit << m_curBit);
				inc();
			}

			template<typename T>
			void write(T value)
			{
				for (int i = 0; i < sizeof(T) * 0x8; i++) {
					writeBit(value >> i & 0b1);
				}
			}

			void write(const void* src, int size) {
				BYTE* data = (BYTE*)src;
				for (int i = 0; i < size; i++)
					write(data[i]);
			}

			bool readBit()
			{
				bool result = m_bytes[m_curByte] >> m_curBit & 0b1;
				inc();
				return result;
			}

			template<typename T>
			T read()
			{
				T result = 0;
				for (int i = 0; i < sizeof(T) * 0x8; i++) {
					result |= readBit() << i;
				}
				return result;
			}

			void read(void* dst, int size) {
				BYTE* data = (BYTE*)dst;
				for (int i = 0; i < size; i++)
					data[i] = read<BYTE>();
			}

			void setData(BYTE* data, int size) {
				for (int i = 0; i < size; i++) {
					m_bytes.push_back(data[i]);
				}
			}

			BYTE* getData() {
				return m_bytes.data();
			}

			int getSize() {
				return m_curByte;
			}

			void resetPointer() {
				m_curByte = 0;
				m_curBit = 0;
			}
		private:
			inline void inc() {
				if (++m_curBit == 0x8 * sizeof(BYTE)) {
					m_curByte++;
					m_curBit = 0;
					if(m_curByte == m_bytes.size())
						m_bytes.push_back(0);
				}
			}

			int m_curByte;
			int m_curBit;
			std::vector<BYTE> m_bytes;
		};
	};






	class TypeManager;
	class GVarManager;
	class FunctionManager;
	class VtableManager;
	class TriggerManager;
	class StatManager;

	class SDA
	{
	public:
		SDA(void* addr, FS::Directory dir)
			: m_baseAddr((std::uintptr_t)addr), m_dir(dir)
		{}

		void load();
		void initManagers();
		void initDataBase(std::string filename);

		inline SQLite::Database& getDB() {
			return *m_db;
		}

		inline TypeManager* getTypeManager() {
			return m_typeManager;
		}

		inline GVarManager* getGVarManager() {
			return m_gvarManager;
		}

		inline FunctionManager* getFunctionManager() {
			return m_functionManager;
		}

		inline VtableManager* getVTableManager() {
			return m_vtableManager;
		}

		inline TriggerManager* getTriggerManager() {
			return m_triggerManager;
		}

		inline StatManager* getStatManager() {
			return m_statManager;
		}

		inline std::uintptr_t getBaseAddr() {
			return m_baseAddr;
		}

		void* toAbsAddr(int offset) {
			return (void*)(getBaseAddr() + (std::uintptr_t)offset);
		}

		int toRelAddr(void* addr) {
			return (std::uintptr_t)addr - getBaseAddr();
		}

		FS::Directory& getDirectory() {
			return m_dir;
		}
	private:
		SQLite::Database* m_db = nullptr;
		std::uintptr_t m_baseAddr;
		FS::Directory m_dir;

		TypeManager* m_typeManager = nullptr;
		GVarManager* m_gvarManager = nullptr;
		FunctionManager* m_functionManager = nullptr;
		VtableManager* m_vtableManager = nullptr;
		TriggerManager* m_triggerManager = nullptr;
		StatManager* m_statManager = nullptr;
	};

	class IManager
	{
	public:
		IManager(SDA* sda)
			: m_sda(sda)
		{}
	protected:
		SDA* getSDA() {
			return m_sda;
		}
	private:
		SDA* m_sda;
	};

	class TypeManager : public IManager
	{
	public:
		using TypeDict = std::map<int, Type::Type*>;

		TypeManager(SDA* sda)
			: IManager(sda)
		{
			addSystemTypes();
			addGhidraSystemTypes();
		}

	private:
		void addSystemTypes() {
			addType(new CE::Type::Void);
			addType(new CE::Type::Bool);
			addType(new CE::Type::Byte);
			addType(new CE::Type::Int8);
			addType(new CE::Type::Int16);
			addType(new CE::Type::Int32);
			addType(new CE::Type::Int64);
			addType(new CE::Type::UInt16);
			addType(new CE::Type::UInt32);
			addType(new CE::Type::UInt64);
			addType(new CE::Type::Float);
			addType(new CE::Type::Double);
		}

		inline static std::vector<std::pair<std::string, Type::Type*>> ghidraTypes = {
			std::make_pair("void", new CE::Type::Void),
			std::make_pair("unicode", new CE::Type::Void),
			std::make_pair("string", new CE::Type::Void),

			std::make_pair("char", new CE::Type::Int8),
			std::make_pair("uchar", new CE::Type::Byte),
			std::make_pair("uint8_t", new CE::Type::Byte),
			std::make_pair("undefined1", new CE::Type::Int8),

			std::make_pair("short", new CE::Type::Int16),
			std::make_pair("ushort", new CE::Type::UInt16),
			std::make_pair("wchar_t", new CE::Type::UInt16),
			std::make_pair("word", new CE::Type::Int16),
			std::make_pair("undefined2", new CE::Type::Int16),

			std::make_pair("int", new CE::Type::Int32),
			std::make_pair("uint", new CE::Type::UInt32),
			std::make_pair("long", new CE::Type::Int32),
			std::make_pair("ulong", new CE::Type::UInt32),
			std::make_pair("dword", new CE::Type::Int32),
			std::make_pair("float", new CE::Type::Float),
			std::make_pair("ImageBaseOffset32", new CE::Type::UInt32),
			std::make_pair("undefined4", new CE::Type::Int32),

			std::make_pair("longlong", new CE::Type::Int64),
			std::make_pair("ulonglong", new CE::Type::UInt64),
			std::make_pair("qword", new CE::Type::Int64),
			std::make_pair("double", new CE::Type::Double),
			std::make_pair("undefined8", new CE::Type::Int64),

			std::make_pair("GUID", new CE::Type::UInt128)
		};

		void addGhidraSystemTypes() {
			for (const auto& it : ghidraTypes) {
				createTypedef(it.second, it.first);
			}
		}
	public:
		const std::string& getGhidraName(Type::Type* type) {
			for (const auto& it : ghidraTypes) {
				if (it.second->getId() == type->getId()) {
					return it.first;
				}
			}
			return getGhidraName(getDefaultType());
		}

		void saveType(Type::Type* type) {
			if (!type->isUserDefined()) {
				return;
			}

			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			{
				SQLite::Statement query(db, "REPLACE INTO sda_types (id, `group`, name, desc) VALUES(?1, ?2, ?3, ?4)");
				query.bind(1, type->getId());
				query.bind(2, (int)type->getGroup());
				query.bind(3, type->getName());
				query.bind(4, type->getDesc());
				query.exec();
			}
			if (type->getGroup() == Type::Type::Class) {
				auto Class = (Type::Class*)type;
				SQLite::Statement query(db, "REPLACE INTO sda_classes (class_id, base_class_id, size, vtable_id) VALUES(?1, ?2, ?3, ?4)");
				query.bind(1, Class->getId());
				query.bind(2, Class->getBaseClass() != nullptr ? Class->getBaseClass()->getId() : 0);
				query.bind(3, Class->getRelSize());
				auto vtable = Class->getVtable();
				query.bind(4, vtable == nullptr ? 0 : vtable->getId());
				query.exec();
			}
			else if (type->getGroup() == Type::Type::Typedef) {
				auto Typedef = (Type::Typedef*)type;
				SQLite::Statement query(db, "REPLACE INTO sda_typedefs (type_id, ref_type_id, pointer_lvl, array_size) VALUES(?1, ?2, ?3, ?4)");
				query.bind(1, Typedef->getId());
				query.bind(2, Typedef->getRefType()->getId());
				query.bind(3, Typedef->getRefType()->getPointerLvl());
				query.bind(4, Typedef->getRefType()->getArraySize());
				query.exec();
			}
		}

		void removeType(Type::Type* type) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();

			{
				SQLite::Statement query(db, "DELETE FROM sda_types WHERE id=?1");
				query.bind(1, type->getId());
				query.exec();
			}

			if (type->getGroup() == Type::Type::Class) {
				SQLite::Statement query(db, "DELETE FROM sda_classes WHERE class_id=?1");
				query.bind(1, type->getId());
				query.exec();
			}
			else if (type->getGroup() == Type::Type::Typedef) {
				SQLite::Statement query(db, "DELETE FROM sda_typedefs WHERE type_id=?1");
				query.bind(1, type->getId());
				query.exec();
			}

			auto it = m_types.find(type->getId());
			if (it != m_types.end()) {
				m_types.erase(it);
			}
		}

		int getNewId() {
			int id = 1;
			while (m_types.find(id) != m_types.end())
				id++;
			return id;
		}

		Type::Typedef* createTypedef(Type::Type* refType, std::string name, std::string desc = "") {
			int id = getNewId();
			auto type = new Type::Typedef(refType, id, name, desc);
			m_types[id] = type;
			return type;
		}

		Type::Enum* createEnum(std::string name, std::string desc = "") {
			int id = getNewId();
			auto type = new Type::Enum(id, name, desc);
			m_types[id] = type;
			return type;
		}

		Type::Class* createClass(std::string name, std::string desc = "") {
			int id = getNewId();
			auto type = new Type::Class(id, name, desc);
			m_types[id] = type;
			return type;
		}

		void saveEnumFields(Type::Enum* Enum) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_enum_fields WHERE enum_id=?1");
				query.bind(1, Enum->getId());
				query.exec();
			}

			{
				for (auto it : Enum->getFieldDict()) {
					SQLite::Statement query(db, "INSERT INTO sda_enum_fields (enum_id, name, value) VALUES(?1, ?2, ?3)");
					query.bind(1, Enum->getId());
					query.bind(2, it.second);
					query.bind(3, it.first);
					query.exec();
				}
			}

			transaction.commit();
		}

		void saveClassFields(Type::Class* Class) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_class_fields WHERE class_id=?1");
				query.bind(1, Class->getId());
				query.exec();
			}

			{
				for (auto& it : Class->getFieldDict()) {
					SQLite::Statement query(db, "INSERT INTO sda_class_fields (class_id, rel_offset, name, type_id, pointer_lvl, array_size) VALUES(?1, ?2, ?3, ?4, ?5, ?6)");
					query.bind(1, Class->getId());
					query.bind(2, it.first);
					query.bind(3, it.second.getName());
					query.bind(4, it.second.getType()->getId());
					query.bind(5, it.second.getType()->getPointerLvl());
					query.bind(6, it.second.getType()->getArraySize());
					query.exec();
				}
			}

			transaction.commit();
		}

		void saveClassMethods(Type::Class* Class) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_class_methods WHERE class_id=?1");
				query.bind(1, Class->getId());
				query.exec();
			}

			{
				for (auto method : Class->getMethodList()) {
					SQLite::Statement query(db, "INSERT INTO sda_class_fields (class_id, function_id) VALUES(?1, ?2)");
					query.bind(1, Class->getId());
					query.bind(2, method->getId());
					query.exec();
				}
			}

			transaction.commit();
		}

		void loadTypes() {
			using namespace SQLite;
			
			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_types");

			while (query.executeStep())
			{
				Type::Type* type = nullptr;

				int t = query.getColumn("group");
				switch (t)
				{
					case Type::Type::Group::Typedef:
					{
						type = new Type::Typedef(
							getTypeById(Type::SystemType::Byte),
							query.getColumn("id"),
							query.getColumn("name"),
							query.getColumn("desc")
						);
						break;
					}

					case Type::Type::Group::Enum:
					{
						type = new Type::Enum(
							query.getColumn("id"),
							query.getColumn("name"),
							query.getColumn("desc")
						);
						loadFieldsForEnum((Type::Enum*)type);
						break;
					}

					case Type::Type::Group::Class:
					{
						type = new Type::Class(
							query.getColumn("id"),
							query.getColumn("name"),
							query.getColumn("desc")
						);
						break;
					}
				}

				if (type != nullptr) {
					addType(type);
				}
			}
		}

		void loadTypedefs() {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_typedefs");

			while (query.executeStep())
			{
				auto type = getTypeById(query.getColumn("type_id"));
				if (type->getGroup() == Type::Type::Group::Typedef) {
					auto Typedef = (Type::Typedef*)type;
					auto refType = getType(query.getColumn("ref_type_id"), query.getColumn("pointer_lvl"), query.getColumn("array_size"));
					if(refType != nullptr)
						Typedef->setRefType(refType);
				}
			}
		}

		void loadFieldsForEnum(Type::Enum* Enum) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT name,value FROM sda_enum_fields WHERE enum_id=?1 GROUP BY value");
			query.bind(1, Enum->getId());

			while (query.executeStep())
			{
				Enum->addField(query.getColumn("name"), query.getColumn("value"));
			}
		}

		void loadClasses()
		{
			for (auto it : m_types) {
				if (it.second->getGroup() == Type::Type::Group::Class) {
					auto Class = (Type::Class*)it.second;
					loadInfoForClass(Class);
					loadMethodsForClass(Class);
					loadFieldsForClass(Class);
				}
			}
		}

		void loadInfoForClass(Type::Class* Class);
		void loadMethodsForClass(Type::Class* Class);

		void loadFieldsForClass(Type::Class* Class) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_class_fields WHERE class_id=?1 GROUP BY rel_offset");
			query.bind(1, Class->getId());

			while (query.executeStep())
			{
				Type::Type* type = getSDA()->getTypeManager()->getType(
					query.getColumn("type_id"),
					query.getColumn("pointer_lvl"),
					query.getColumn("array_size")
				);

				if (type == nullptr) {
					type = getSDA()->getTypeManager()->getTypeById(Type::SystemType::Byte);
				}
				Class->addField(query.getColumn("rel_offset"), query.getColumn("name"), type);
			}
		}

		Type::Type* getDefaultType() {
			return getTypeById(Type::SystemType::Byte);
		}

		TypeDict& getTypes() {
			return m_types;
		}

		void addType(Type::Type* type) {
			m_types.insert(std::make_pair(type->getId(), type));
		}

		inline Type::Type* getTypeById(int type_id) {
			if (m_types.find(type_id) == m_types.end())
				return nullptr;
			return m_types[type_id];
		}

		Type::Type* getType(Type::Type* type, int pointer_lvl = 0, int array_size = 0) {
			if (pointer_lvl > 0) {
				for (int i = 0; i < pointer_lvl; i++) {
					type = new Type::Pointer(type);
				}
			}

			if (array_size > 0) {
				type = new Type::Array(type, array_size);
			}
			return type;
		}

		Type::Type* getType(int type_id, int pointer_lvl = 0, int array_size = 0) {
			Type::Type* type = getTypeById(type_id);
			if (type != nullptr) {
				type = getType(type, pointer_lvl, array_size);
			}
			return type;
		}
	private:
		TypeDict m_types;
	};

	class GVarManager : public IManager
	{
	public:
		using GVarDict = std::map<int, Variable::Global*>;

		GVarManager(SDA* sda)
			: IManager(sda)
		{}

		void saveGVar(Variable::Global* gVar) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "REPLACE INTO sda_gvars (id, name, offset, type_id, pointer_lvl, array_size, desc) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)");
			query.bind(1, gVar->getId());
			query.bind(2, gVar->getName());
			query.bind(3, getSDA()->toRelAddr(gVar->getAddress()));
			query.bind(4, gVar->getType()->getId());
			query.bind(5, gVar->getType()->getPointerLvl());
			query.bind(6, gVar->getType()->getArraySize());
			query.bind(7, gVar->getDesc());
			query.exec();
		}

		void removeGVar(Variable::Global* gVar) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "DELETE FROM sda_gvars WHERE id=?1");
			query.bind(1, gVar->getId());
			query.exec();

			auto it = m_gvars.find(gVar->getId());
			if (it != m_gvars.end()) {
				m_gvars.erase(it);
			}
		}

		int getNewId() {
			int id = 1;
			while (m_gvars.find(id) != m_gvars.end())
				id++;
			return id;
		}

		Variable::Global* createGVar(Type::Type* type, void* addr, std::string name, std::string desc = "") {
			int id = getNewId();
			auto gvar = new Variable::Global(type, addr, id, name, desc);
			m_gvars[id] = gvar;
			return gvar;
		}

		void loadGVars() {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_gvars");

			while (query.executeStep())
			{
				Type::Type* type = getSDA()->getTypeManager()->getType(
					query.getColumn("type_id"),
					query.getColumn("pointer_lvl"),
					query.getColumn("array_size")
				);

				if (type == nullptr) {
					type = getSDA()->getTypeManager()->getTypeById(Type::SystemType::Byte);
				}

				Variable::Global* gvar = new Variable::Global(
					type,
					getSDA()->toAbsAddr(query.getColumn("offset")),
					query.getColumn("id"),
					query.getColumn("name"),
					query.getColumn("desc")
				);
					
				addGVar(gvar);
			}
		}

		void addGVar(Variable::Global* gvar) {
			m_gvars.insert(std::make_pair(gvar->getId(), gvar));
		}

		inline Variable::Global* getGVarById(int id) {
			return m_gvars[id];
		}
	private:
		GVarDict m_gvars;
	};

	class FunctionManager : public IManager
	{
	public:
		using FunctionDict = std::map<int, Function::Function*>;

		FunctionManager(SDA* sda)
			: IManager(sda)
		{
			createDefaultFunction();
		}

		Function::Function* getDefaultFunction() {
			return m_defFunction;
		}
	private:
		Function::Function* m_defFunction = nullptr;
		void createDefaultFunction() {
			m_defFunction = createFunction(nullptr, {}, "DefaultFunction", "This function created automatically.");
		}


		void saveFunctionNodeGroup(Function::Function* function, CallGraph::NodeGroup* nodeGroup, int& id) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			bool goToParent = false;

			for (auto node : nodeGroup->getNodeList())
			{
				{
					SQLite::Statement query(db, "INSERT INTO sda_callnodes (function_id, id, item_group, item_id, extra) VALUES (?1, ?2, ?3, ?4, ?5)");
					query.bind(1, function->getId());
					query.bind(2, id++);
					query.bind(3, (int)node->getGroup());
						
					int extra = 0;
					int item_id = 0;
					Utils::BitStream bs((BYTE*)&extra, sizeof(int));

					if (goToParent) {
						bs.writeBit(1);
						goToParent = false;
					}
					else {
						bs.writeBit(0);
					}

					switch (node->getGroup())
					{
					case CallGraph::Type::Function:
						item_id = ((CallGraph::FunctionNode*)node)->getFunction()->getId();
						break;
					case CallGraph::Type::GlobalVar:
					{
						auto gvarNode = (CallGraph::GlobalVarNode*)node;
						item_id = gvarNode->getGVar()->getId();
						bs.writeBit(gvarNode->getUse());
						break;
					}
					case CallGraph::Type::NodeGroup:
						break;
					case CallGraph::Type::Cycle:
						break;
					case CallGraph::Type::Condition:
						break;
					case CallGraph::Type::FunctionBody:
						break;
					}

					query.bind(4, item_id);
					query.bind(5, extra);
				}

				if (nodeGroup->getGroup() >= CallGraph::Type::NodeGroup) {
					goToParent = true;
					saveFunctionNodeGroup(function, nodeGroup, id);
				}
			}
		}
	public:
		void saveFunctionBody(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_callnodes WHERE function_id=?1");
				query.bind(1, function->getId());
				query.exec();
			}

			int id = 0;
			saveFunctionNodeGroup(function, function->getBody(), id);
			transaction.commit();
		}

		void saveFunctionArguments(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_func_arguments WHERE function_id=?1");
				query.bind(1, function->getId());
				query.exec();
			}

			{
				int id = 0;
				for (auto type : function->getSignature().getArgList()) {
					SQLite::Statement query(db, "INSERT INTO sda_func_arguments (function_id, id, name, type_id, pointer_lvl, array_size) \
					VALUES(?1, ?2, ?3, ?4, ?5, ?6)");
					query.bind(1, function->getId());
					query.bind(2, id);
					query.bind(3, function->getArgNameList()[id]);
					query.bind(4, type->getId());
					query.bind(5, type->getPointerLvl());
					query.bind(6, type->getArraySize());
					query.exec();
					id++;
				}
			}

			transaction.commit();
		}

		void saveFunctionRanges(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_func_ranges WHERE function_id=?1");
				query.bind(1, function->getId());
				query.exec();
			}

			{
				int order_id = 0;
				for (auto& range : function->getRangeList()) {
					SQLite::Statement query(db, "INSERT INTO sda_func_ranges (function_id, order_id, min_offset, max_offset) \
					VALUES(?1, ?2, ?3, ?4)");
					query.bind(1, function->getId());
					query.bind(2, order_id);
					query.bind(3, getSDA()->toRelAddr(range.getMinAddress()));
					query.bind(4, getSDA()->toRelAddr(range.getMaxAddress()));
					query.exec();
					order_id++;
				}
			}

			transaction.commit();
		}

		void saveFunction(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "REPLACE INTO sda_functions (id, name, method, offset, ret_type_id, ret_pointer_lvl, ret_array_size, desc)\
				VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
			query.bind(1, function->getId());
			query.bind(2, function->getName());
			query.bind(3, function->isMethod());
			query.bind(4, getSDA()->toRelAddr(function->getAddress()));
			query.bind(5, function->getSignature().getReturnType()->getId());
			query.bind(6, function->getSignature().getReturnType()->getPointerLvl());
			query.bind(7, function->getSignature().getReturnType()->getArraySize());
			query.bind(8, function->getDesc());
			query.exec();
		}

		void saveFunctions() {
			for (auto it : m_functions) {
				auto func = it.second;
				saveFunction(func);
				saveFunctionRanges(func);
				if (func->m_argumentsChanged) {
					saveFunctionArguments(func);
				}
			}
		}

		void removeFunction(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "DELETE FROM sda_functions WHERE id=?1");
			query.bind(1, function->getId());
			query.exec();

			auto it = m_functions.find(function->getId());
			if (it != m_functions.end()) {
				m_functions.erase(it);
			}
		}

		int getNewId() {
			int id = 1;
			while (m_functions.find(id) != m_functions.end())
				id++;
			return id;
		}

		Function::Function* createFunction(void* addr, Function::Function::RangeList ranges, std::string name, std::string desc = "") {
			int id = getNewId();
			auto func = new Function::Function(addr, ranges, id, name, desc);
			m_functions[id] = func;
			func->getSignature().setReturnType(getSDA()->getTypeManager()->getTypeById(Type::SystemType::Void));
			return func;
		}

		Function::Function* createFunction(Function::Function::RangeList ranges, std::string name, std::string desc = "") {
			return createFunction(ranges[0].getMinAddress(), ranges, name, desc);
		}

		Function::Method* createMethod(Type::Class* Class, void* addr, Function::Function::RangeList size, std::string name, std::string desc = "") {
			int id = getNewId();
			auto method = new Function::Method(addr, size, id, name, desc);
			m_functions[id] = method;
			method->getSignature().setReturnType(getSDA()->getTypeManager()->getTypeById(Type::SystemType::Void));
			Class->addMethod(method);
			return method;
		}

		void loadFunctions() {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_functions");

			while (query.executeStep())
			{
				Function::Function* function;
				if ((int)query.getColumn("method") == 0) {
					function = new Function::Function(
						getSDA()->toAbsAddr(query.getColumn("offset")),
						Function::Function::RangeList(),
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
				}
				else {
					function = new Function::Method(
						getSDA()->toAbsAddr(query.getColumn("offset")),
						Function::Function::RangeList(),
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
				}

				Type::Type* type = getSDA()->getTypeManager()->getType(
					query.getColumn("ret_type_id"),
					query.getColumn("ret_pointer_lvl"),
					query.getColumn("ret_array_size")
				);
				if (type == nullptr) {
					type = getSDA()->getTypeManager()->getTypeById(Type::SystemType::Void);
				}
				function->getSignature().setReturnType(type);

				loadFunctionRanges(function);
				loadFunctionArguments(function);
				addFunction(function);
				function->m_argumentsChanged = false;
			}
		}

		void loadFunctionRanges(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_func_ranges WHERE function_id=?1 GROUP BY order_id");
			query.bind(1, function->getId());

			while (query.executeStep())
			{
				function->addRange(Function::Function::Range(
					getSDA()->toAbsAddr(query.getColumn("min_offset")),
					getSDA()->toAbsAddr(query.getColumn("max_offset"))
				));
			}
		}

		void loadFunctionArguments(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_func_arguments WHERE function_id=?1 GROUP BY id");
			query.bind(1, function->getId());

			while (query.executeStep())
			{
				Type::Type* type = getSDA()->getTypeManager()->getType(
					query.getColumn("type_id"),
					query.getColumn("pointer_lvl"),
					query.getColumn("array_size")
				);

				if (type == nullptr) {
					type = getSDA()->getTypeManager()->getTypeById(Type::SystemType::Byte);
				}

				function->addArgument(type, query.getColumn("name"));
			}
		}

		void loadFunctionBody(Function::Function* function) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_callnodes WHERE function_id=?1 GROUP BY id");
			query.bind(1, function->getId());

			CallGraph::FunctionBody* body = new CallGraph::FunctionBody;
			function->setBody(body);

			CallGraph::NodeGroup* nodeGroup = body;
			while (query.executeStep())
			{
				Utils::BitStream bs;
				bool goToParentNode = false;
				{
					int extra = query.getColumn("extra");
					bs.setData((BYTE*)& extra, sizeof(extra));
					goToParentNode = bs.readBit();
				}
				CallGraph::Node* node = nullptr;

				switch ((CallGraph::Type)(int)query.getColumn("item_group"))
				{
					case CallGraph::Type::Function:
					{
						Function::Function* function = getSDA()->getFunctionManager()->getFunctionById(query.getColumn("item_id"));
						if (function != nullptr) {
							node = new CallGraph::FunctionNode(function);
						}
						break;
					}

					case CallGraph::Type::GlobalVar:
					{
						Variable::Global* gvar = getSDA()->getGVarManager()->getGVarById(query.getColumn("item_id"));
						if (gvar != nullptr) {
							node = new CallGraph::GlobalVarNode(gvar, (CallGraph::GlobalVarNode::Use)bs.readBit());
						}
						break;
					}

					case CallGraph::Type::NodeGroup:
						node = new CallGraph::NodeGroup;
						break;
					case CallGraph::Type::Cycle:
						node = new CallGraph::Cycle;
						break;
					case CallGraph::Type::Condition:
						node = new CallGraph::Condition;
						break;
					case CallGraph::Type::FunctionBody:
						node = new CallGraph::FunctionBody;
						break;
				}

				if (node != nullptr) {
					if (goToParentNode) {
						nodeGroup = nodeGroup->getParent();
					}
					nodeGroup->addNode(node);
					if (node->getGroup() >= CallGraph::Type::NodeGroup) {
						nodeGroup = (CallGraph::NodeGroup*)node;
					}
				}
			}
		}

		void loadFunctionBodies() {
			for (auto it : m_functions) {
				loadFunctionBody(it.second);
			}
		}

		FunctionDict& getFunctions() {
			return m_functions;
		}

		void addFunction(Function::Function* function) {
			m_functions.insert(std::make_pair(function->getId(), function));
		}

		inline Function::Function* getFunctionById(int id) {
			if (m_functions.find(id) == m_functions.end())
				return nullptr;
			return m_functions[id];
		}

		int getFunctionOffset(Function::Function* function) {
			return getSDA()->toRelAddr(function->getAddress());
		}
	private:
		FunctionDict m_functions;
	};

	class VtableManager : public IManager
	{
	public:
		using VTableDict = std::map<int, Function::VTable*>;

		VtableManager(SDA* sda)
			: IManager(sda)
		{}

		void saveVTable(Function::VTable* vtable) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "REPLACE INTO sda_vtables (id, name, offset, desc) VALUES(?1, ?2, ?3, ?4)");
			query.bind(1, vtable->getId());
			query.bind(2, vtable->getName());
			query.bind(3, getSDA()->toRelAddr(vtable->getAddress()));
			query.bind(4, vtable->getDesc());
			query.exec();
		}

		void saveFunctionsForVTable(Function::VTable* vtable) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_vtable_funcs WHERE function_id=?1");
				query.bind(1, vtable->getId());
				query.exec();
			}

			{
				int id = 0;
				for (auto method : vtable->getVMethodList()) {
					SQLite::Statement query(db, "INSERT INTO sda_vtable_funcs (vtable_id, function_id, id) VALUES(?1, ?2, ?3)");
					query.bind(1, vtable->getId());
					query.bind(2, method->getId());
					query.bind(3, id);
					query.exec();
					id++;
				}
			}

			transaction.commit();
		}

		void removeVTable(Function::VTable* vtable) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "DELETE FROM sda_vtables WHERE id=?1");
			query.bind(1, vtable->getId());
			query.exec();

			auto it = m_vtables.find(vtable->getId());
			if (it != m_vtables.end()) {
				m_vtables.erase(it);
			}
		}

		int getNewId() {
			int id = 1;
			while (m_vtables.find(id) != m_vtables.end())
				id++;
			return id;
		}

		Function::VTable* createVTable(void* addr, std::string name, std::string desc = "") {
			int id = getNewId();
			auto vtable = new Function::VTable(addr, id, name, desc);
			m_vtables[id] = vtable;
			return vtable;
		}

		void loadVTables()
		{
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_vtables");

			while (query.executeStep())
			{
				Function::VTable* vtable = new Function::VTable(
					getSDA()->toAbsAddr(query.getColumn("offset")),
					query.getColumn("id"),
					query.getColumn("name"),
					query.getColumn("desc")
				);

				loadFunctionsForVTable(vtable);
				addVTable(vtable);
			}
		}

		void loadFunctionsForVTable(Function::VTable* vtable)
		{
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT function_id FROM sda_vtable_funcs WHERE vtable_id=?1 GROUP BY id");
			query.bind(1, vtable->getId());

			while (query.executeStep())
			{
				Function::Function* function = getSDA()->getFunctionManager()->getFunctionById(query.getColumn("function_id"));
				if (function != nullptr && function->isMethod()) {
					vtable->addMethod((Function::Method*)function);
				}
			}
		}

		void addVTable(Function::VTable* vtable) {
			m_vtables.insert(std::make_pair(vtable->getId(), vtable));
		}

		inline Function::VTable* getVTableById(int vtable_id) {
			if (m_vtables.find(vtable_id) == m_vtables.end())
				return nullptr;
			return m_vtables[vtable_id];
		}
	private:
		VTableDict m_vtables;
	};




	namespace Trigger
	{
		namespace Function
		{
			class Trigger;
		};
	};

	namespace Stat
	{
		class Analyser
		{
		public:
			Analyser()
			{}

			class Histogram
			{
			public:
				struct Interval
				{
					double m_left;
					double m_right;
					Interval(double a, double b)
						: m_left(a), m_right(b)
					{}
					
					double getMiddle() {
						return (m_right + m_left) / 2.0;
					}

					bool isPoint() {
						return m_left == m_right;
					}
				};

				struct Column
				{
					Interval m_interval;
					int m_frequency;
					Column(Interval interval, int frequency)
						: m_interval(interval), m_frequency(frequency)
					{}
				};

				Column& getColumn(int index) {
					return m_columns[index];
				}

				void addColumn(Column column) {
					m_columns.push_back(column);
				}

				int getColumnCount() {
					return m_columns.size();
				}

				int getTotalCount() {
					int result = 0;
					for (const auto& column : m_columns) {
						result += column.m_frequency;
					}
					return result;
				}

				double getBeginingMoment(int degree) {
					double result = 0.0;
					for (auto& column : m_columns) {
						result += ((double)column.m_frequency / getTotalCount()) * pow(column.m_interval.getMiddle(), degree);
					}
					return result;
				}

				double getMiddle() {
					return getBeginingMoment(1);
				}

				double getVariance2() {
					return getBeginingMoment(2) - pow(getBeginingMoment(1), 2);
				}

				double getVariance() {
					return sqrt(getVariance2());
				}

				double getMin() {
					return m_columns.begin()->m_interval.m_left;
				}

				double getMax() {
					return m_columns.rbegin()->m_interval.m_right;
				}

				void debugShow()
				{
					printf(" Histogram{E=%.1f,V=%.2f,min=%.1f,max=%.1f; ", (float)getMiddle(), (float)getVariance(), (float)getMin(), (float)getMax());
					for (auto& column : m_columns) {
						printf("[%.1f,%.1f=>%i] ", (float)column.m_interval.m_left, (float)column.m_interval.m_right, column.m_frequency);
					}
				}
			private:
				std::vector<Column> m_columns;
			};

			bool hasValue(uint64_t value) {
				return m_rawValues.find(value) != m_rawValues.end();
			}

			template<typename T = uint64_t>
			void addValue(T value) {
				uint64_t rawValue = (uint64_t&)value;
				if (hasValue(rawValue)) {
					m_rawValues[rawValue] ++;
				}
				else {
					m_rawValues[rawValue] = 1;
				}
			}

			void doAnalyse()
			{
				using namespace CE::Type;

				if (m_rawValues.size() == 0)
					return;

				if (isRealInRange<float>({
					std::make_pair(0.0001, 10000.0),
					std::make_pair(-10000.0, -0.0001),
					std::make_pair(0.0, 0.0) 
				})) {
					m_set = SystemType::Real;
					m_typeId = SystemType::Float;
				} else if (isRealInRange<double>({
					std::make_pair(0.00001, 100000.0),
					std::make_pair(-100000.0, -0.00001),
					std::make_pair(0.0, 0.0)
				})) {
					m_set = SystemType::Real;
					m_typeId = SystemType::Double;
				}

				if (m_rawValues.size() == 1) {
					if (getMin<BYTE>() == 0 && getMin<BYTE>() == 1) {
						m_set = SystemType::Boolean;
					}
					else {
						if (m_set != SystemType::Real) {
							m_set = SystemType::Integer;
						}
					}
				}
				else if (m_rawValues.size() == 2) {
					if (getMin<BYTE>() == 0 && getMax<BYTE>() == 1) {
						m_set = SystemType::Boolean;
					}
				}
				else {
					if (m_set == SystemType::Undefined) {
						m_set = SystemType::Integer;
					}
				}
			}

			Histogram* createHistogram()
			{
				using namespace CE::Type;

				Histogram* histogram = new Histogram;
				switch (getSet())
				{
					case SystemType::Boolean:
					{
						for (uint64_t value = 0; value <= 1; value++) {
							histogram->addColumn(Histogram::Column(
								Histogram::Interval((float)value, (float)value),
								hasValue(value) ? m_rawValues[value] : 0
							));
						}
						break;
					}

					case SystemType::Integer:
					{
						switch (getTypeId())
						{
						case SystemType::Int8:
							fillHistogramWithColumns<int8_t>(*histogram);
							break;
						case SystemType::Int16:
							fillHistogramWithColumns<int16_t>(*histogram);
							break;
						case SystemType::Int32:
							fillHistogramWithColumns<int32_t>(*histogram);
							break;
						case SystemType::Int64:
							fillHistogramWithColumns<int64_t>(*histogram);
							break;
						default:
							fillHistogramWithColumns<uint64_t>(*histogram);
						}
						break;
					}

					case SystemType::Real:
					{
						switch (getTypeId())
						{
						case SystemType::Float:
							fillHistogramWithColumns<float>(*histogram);
							break;
						case SystemType::Double:
							fillHistogramWithColumns<double>(*histogram);
							break;
						}
						break;
					}
				}
				return histogram;
			}
			
			bool isUndefined() {
				return getSet() == Type::SystemType::Undefined;
			}

			Type::SystemType::Set getSet() {
				return m_set;
			}

			Type::SystemType::Types getTypeId() {
				return m_typeId;
			}

			void setTypeId(Type::SystemType::Types typeId) {
				m_typeId = typeId;
			}
		private:
			template<typename T = uint64_t>
			T getMin() {
				T result = (T)0x0;
				bool isFirst = true;
				for (auto& it : m_rawValues) {
					if (isFirst || (T&)it.first < result) {
						result = (T&)it.first;
						isFirst = false;
					}
				}
				return result;
			}


			template<typename T = uint64_t>
			T getMax() {
				T result = (T)0x0;
				bool isFirst = true;
				for (auto& it : m_rawValues) {
					if (isFirst || (T&)it.first > result) {
						result = (T&)it.first;
						isFirst = false;
					}
				}
				return result;
			}

			template<typename T>
			bool isRealInRange(std::vector<std::pair<T, T>> ranges) {
				for (auto& it : m_rawValues) {
					bool result = false;
					for (auto& range : ranges) {
						if ((T&)it.first >= range.first && (T&)it.first <= range.second) {
							result = true;
						}
					}
					if (!result) {
						return false;
					}
				}
				return true;
			}

			template<typename T>
			void fillHistogramWithColumns(Histogram& histogram)
			{
				double min = getMin<T>();
				double max = getMax<T>();
				double step = (max - min) / getColumnCount();
				for (int i = 0; i < getColumnCount(); i++) {
					auto interval = Histogram::Interval(min + step * i, min + step * (i + 1));
					histogram.addColumn(Histogram::Column(
						interval,
						getValueCountInInterval<T>(interval, i == 0)
					));
				}
			}

			template<typename T>
			int getValueCountInInterval(const Histogram::Interval& interval, bool leftBoundaryInclude = false) {
				int count = 0;
				for (auto& it : m_rawValues) {
					if ((double)(T&)it.first > interval.m_left - leftBoundaryInclude * 0.01 && (double)(T&)it.first <= interval.m_right) {
						count += it.second;
					}
				}
				return count;
			}

			int getColumnCount() {
				return floor(log2(m_rawValues.size())) + 1;
			}
		private:
			Type::SystemType::Set m_set = Type::SystemType::Undefined;
			Type::SystemType::Types m_typeId = Type::SystemType::Void;
			std::map<uint64_t, int> m_rawValues;
		};

		namespace Function
		{
			template<typename T>
			class IGarbager
			{
			public:
				IGarbager(StatManager* statManager = nullptr)
					: m_statManager(statManager)
				{}

				~IGarbager() {
					if (m_db != nullptr) {
						delete m_db;
					}
				}

				void start() {
					m_thread = std::thread(&IGarbager<T>::handler, this);
					m_thread.detach();
				}

				void initDataBase(FS::File file)
				{
					if (m_db != nullptr) {
						delete m_db;
					}
					m_db = new SQLite::Database(file.getFilename(), SQLite::OPEN_READWRITE);
				}

				virtual void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook) = 0;
				
				int getSize() {
					return m_buffers.size();
				}

				SQLite::Database& getDB() {
					return *m_db;
				}

				virtual void copyStatTo(SQLite::Database& db) {};
				virtual void clear() {}
			protected:
				virtual void handler() = 0;

				std::queue<T> m_buffers;
				std::mutex m_bufferMutex;
				std::mutex m_dbMutex;
				std::thread m_thread;

				StatManager* m_statManager;
				SQLite::Database* m_db = nullptr;
			};

			template<typename B, typename G = IGarbager<B>>
			class IManager
			{
			public:
				inline void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
				{
					selectGarbager1()->add(trigger, hook);
					//m_counter++;
				}

				IGarbager<B>* selectGarbager1() {
					IGarbager<B>* result = nullptr;
					int size = INT_MAX;
					for (IGarbager<B>* garbager : m_garbagers) {
						if (garbager->getSize() < size) {
							result = garbager;
							size = garbager->getSize();
						}
					}
					return result;
				}

				IGarbager<B>* selectGarbager2() {
					return m_garbagers[m_counter % m_garbagers.size()];
				}

				void copyStatTo(SQLite::Database& db)
				{
					for (auto it : m_garbagers) {
						it->copyStatTo(db);
						it->clear();
					}
				}

				void addGarbager(IGarbager<B>* garbager)
				{
					m_garbagers.push_back(garbager);
				}
			protected:
				std::vector<IGarbager<B>*> m_garbagers;
				std::atomic<uint64_t> m_counter = 0;
			};

			namespace Args
			{
				class Buffer
				{
				public:
					uint64_t m_uid = 0;
					uint64_t m_args[12] = {0};
					uint64_t m_xmm_args[4] = {0};
					CE::Hook::DynHook* m_hook = nullptr;
					CE::Trigger::Function::Trigger* m_trigger = nullptr;

					Buffer(CE::Hook::DynHook* hook, CE::Trigger::Function::Trigger* trigger)
					{
						m_uid = hook->getUID();
						for (int i = 1; i <= hook->getArgCount(); i++) {
							m_args[i - 1] = hook->getArgumentValue(i);
						}
						if (hook->isXmmSaved()) {
							for (int i = 1; i <= min(4, hook->getArgCount()); i++) {
								m_xmm_args[i - 1] = hook->getXmmArgumentValue(i);
							}
						}
						m_hook = hook;
						m_trigger = trigger;
					}

					inline CE::Function::Function* getFunction() {
						return (CE::Function::Function*)m_hook->getUserPtr();
					}
				};

				class Garbager : public IGarbager<Buffer>
				{
				public:
					Garbager(StatManager* statManager)
						: IGarbager<Buffer>(statManager)
					{}

					void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook) override;
					
					void handler() override {
						while (true)
						{
							m_bufferMutex.lock();
							if (m_buffers.empty()) {
								m_bufferMutex.unlock();
								Sleep(50);
								continue;
							}

							m_dbMutex.lock();
							SQLite::Transaction transaction(getDB());

							for (int i = 0; i < m_buffers.size(); i++) {
								send(m_buffers.front());
								m_buffers.pop();

								static std::atomic<uint64_t> g_counter = 0;
								g_counter++;
								int c = g_counter;
								if (c % 10000 == 0) {
									printf("\n%i) Args", c);
								}
							}
							m_bufferMutex.unlock();

							
							transaction.commit();
							m_dbMutex.unlock();
							Sleep(30);
						}
					}

					void copyStatTo(SQLite::Database& db)
					{
						m_dbMutex.lock();
						{
							SQLite::Statement query(db, "ATTACH DATABASE ?1 AS call_before");
							query.bind(1, getDB().getFilename());
							query.exec();
						}

						{
							SQLite::Statement query(db, "INSERT INTO sda_call_before SELECT * FROM call_before.sda_call_before");
							query.exec();
						}

						{
							SQLite::Statement query(db, "INSERT INTO sda_call_args SELECT * FROM call_before.sda_call_args");
							query.exec();
						}

						{
							SQLite::Statement query(db, "DETACH DATABASE call_before");
							query.exec();
						}
						m_dbMutex.unlock();
					}

					void clear() override
					{
						{
							SQLite::Statement query(getDB(), "DELETE FROM sda_call_before");
							query.exec();
						}
						{
							SQLite::Statement query(getDB(), "DELETE FROM sda_call_args");
							query.exec();
						}
						{
							SQLite::Statement query(getDB(), "VACUUM");
							query.exec();
						}
					}

					void send(Buffer& buffer);
				};

				class Manager : public IManager<Buffer, Garbager> {};
			};

			namespace Ret
			{
				class Buffer
				{
				public:
					uint64_t m_uid = 0;
					uint64_t m_ret = 0;
					uint64_t m_xmm_ret = 0;
					CE::Hook::DynHook* m_hook = nullptr;
					CE::Trigger::Function::Trigger* m_trigger = nullptr;

					Buffer(CE::Hook::DynHook* hook, CE::Trigger::Function::Trigger* trigger)
					{
						m_uid = hook->getUID();
						m_ret = hook->getReturnValue();
						m_xmm_ret = hook->getXmmReturnValue();
						m_hook = hook;
						m_trigger = trigger;
					}

					inline CE::Function::Function* getFunction() {
						return (CE::Function::Function*)m_hook->getUserPtr();
					}
				};

				class Garbager : public IGarbager<Buffer>
				{
				public:
					Garbager(StatManager* statManager)
						: IGarbager<Buffer>(statManager)
					{}

					void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook) override;

					void handler() override {
						while (true)
						{
							m_bufferMutex.lock();
							if (m_buffers.empty()) {
								m_bufferMutex.unlock();
								Sleep(50);
								continue;
							}
							m_dbMutex.lock();
							SQLite::Transaction transaction(getDB());

							for (int i = 0; i < m_buffers.size(); i++) {
								send(m_buffers.front());
								m_buffers.pop();

								static std::atomic<uint64_t> g_counter = 0;
								g_counter++;
								int c = g_counter;
								if (c % 10000 == 0) {
									printf("\n%i) Ret", c);
								}
							}
							m_bufferMutex.unlock();

							transaction.commit();
							m_dbMutex.unlock();
							Sleep(30);
						}
					}

					void copyStatTo(SQLite::Database& db)
					{
						m_dbMutex.lock();
						{
							SQLite::Statement query(db, "ATTACH DATABASE ?1 AS call_after");
							query.bind(1, getDB().getFilename());
							query.exec();
						}

						{
							SQLite::Statement query(db, "INSERT INTO sda_call_after SELECT * FROM call_after.sda_call_after");
							query.exec();
						}

						{
							SQLite::Statement query(db, "DETACH DATABASE call_after");
							query.exec();
						}
						m_dbMutex.unlock();
					}

					void clear() override
					{
						{
							SQLite::Statement query(getDB(), "DELETE FROM sda_call_after");
							query.exec();
						}
						{
							SQLite::Statement query(getDB(), "VACUUM");
							query.exec();
						}
					}

					void send(Buffer& buffer);
				};

				class Manager : public IManager<Buffer, Garbager> {};
			};

			class StatInfo
			{
			public:
				StatInfo()
				{}

				struct Value
				{
					CE::Type::SystemType::Set m_set = CE::Type::SystemType::Undefined;
					CE::Type::SystemType::Types m_typeId = CE::Type::SystemType::Void;
					Analyser::Histogram* m_histogram = nullptr;

					Value() = default;

					Value(CE::Type::SystemType::Set set, CE::Type::SystemType::Types typeId, Analyser::Histogram* histogram)
						: m_set(set), m_typeId(typeId), m_histogram(histogram)
					{}
				};

				void addArgument(Value value) {
					m_args.push_back(value);
				}

				void setReturnValue(const Value& value) {
					m_ret = value;
				}

				Value& getArgument(int index) {
					return m_args[index];
				}

				Value& getReturnValue() {
					return m_ret;
				}

				void debugShow()
				{
					printf("\nStatistic of the function\n\nReturn value: ");
					getReturnValue().m_histogram->debugShow();
					for (int i = 0; i < m_args.size(); i++) {
						printf("\nArgument %i: ", i + 1);
						if(getArgument(i).m_set != CE::Type::SystemType::Undefined)
							getArgument(i).m_histogram->debugShow();
					}
				}
			private:
				std::vector<Value> m_args;
				Value m_ret;
			};

			class Account
			{
			public:
				Account(SQLite::Database* db, CE::Function::Function* function)
					: m_db(db), m_function(function)
				{}

				struct CallInfo
				{
					uint64_t m_uid;
					uint64_t m_args[12];
					uint64_t m_xmm_args[4];
					uint64_t m_ret;
					uint64_t m_xmm_ret;
				};

				void iterateCalls(std::function<void(CallInfo & info)> handler, CE::Trigger::Function::Trigger* trigger, int page, int pageSize = 30);

				static StatInfo::Value getValueByAnalysers(Analyser& analyser, Analyser& analyser_xmm, CE::Type::Type* type)
				{
					using namespace CE::Type;
					Analyser& result = analyser;
					if (!analyser.isUndefined() && !analyser_xmm.isUndefined()) {
						if (SystemType::GetNumberSetOf(type) == SystemType::Real) {
							analyser = analyser_xmm;
						}
					}
					else if (!analyser_xmm.isUndefined()) {
						analyser = analyser_xmm;
					}
					return StatInfo::Value(result.getSet(), result.getTypeId(), result.createHistogram());
				}

				StatInfo* createStatInfo(CE::Trigger::Function::Trigger* trigger = nullptr);


				SQLite::Database& getDB() {
					return *m_db;
				}
			private:
				CE::Function::Function* m_function;
				SQLite::Database* m_db;
			};
		};
	};

	class StatManager : public IManager
	{
	public:
		StatManager(SDA* sda)
			: IManager(sda)
		{
			m_funcArgManager = new Stat::Function::Args::Manager;
			m_funcRetManager = new Stat::Function::Ret::Manager;
			initGeneralDB();
			initGarbagers(1);
		}

		void initGarbagers(int amount) {
			for (int i = 1; i <= amount; i++)
			{
				{
					auto garbager = new Stat::Function::Args::Garbager(this);
					garbager->initDataBase(
						FS::File(
							getSDA()->getDirectory().next("garbagers"),
							"call_before"+ std::to_string(i) +".db"
						)
					);
					//garbager->clear();
					garbager->start();
					getFuncArgManager()->addGarbager(garbager);
				}

				{
					auto garbager = new Stat::Function::Ret::Garbager(this);
					garbager->initDataBase(
						FS::File(
							getSDA()->getDirectory().next("garbagers"),
							"call_after" + std::to_string(i) + ".db"
						)
					);
					//garbager->clear();
					garbager->start();
					getFuncRetManager()->addGarbager(garbager);
				}
			}
		}

		void initGeneralDB()
		{
			m_general_db = new SQLite::Database(FS::File(getSDA()->getDirectory(), "general_stat.db").getFilename(), SQLite::OPEN_READWRITE);
		}

		void updateGeneralDB()
		{
			getFuncArgManager()->copyStatTo(getDB());
			getFuncRetManager()->copyStatTo(getDB());
		}

		void clearGeneralDB()
		{
			{
				SQLite::Statement query(getDB(), "DELETE FROM sda_call_before");
				query.exec();
			}
			{
				SQLite::Statement query(getDB(), "DELETE FROM sda_call_args");
				query.exec();
			}
			{
				SQLite::Statement query(getDB(), "DELETE FROM sda_call_after");
				query.exec();
			}
			{
				SQLite::Statement query(getDB(), "VACUUM");
				query.exec();
			}
		}
	public:
		inline Stat::Function::Args::Manager* getFuncArgManager() {
			return m_funcArgManager;
		}

		inline Stat::Function::Ret::Manager* getFuncRetManager() {
			return m_funcRetManager;
		}

		SQLite::Database& getDB() {
			return *m_general_db;
		}
	private:
		SQLite::Database* m_general_db = nullptr;
		Stat::Function::Args::Manager* m_funcArgManager;
		Stat::Function::Ret::Manager* m_funcRetManager;
	};

	

	namespace Trigger
	{
		enum Type
		{
			FunctionTrigger
		};

		class ITrigger : public Desc
		{
		public:
			ITrigger(int id, std::string name, std::string desc = "")
				: Desc(id, name, desc)
			{}

			virtual Type getType() = 0;
		};

		namespace Function
		{
			class Hook;
			namespace Filter
			{
				enum class Id
				{
					Empty,
					Object,
					Argument,
					ReturnValue
				};

				class IFilter
				{
				public:
					virtual Id getId() = 0;

					virtual bool checkFilterBefore(CE::Hook::DynHook* hook) {
						return m_beforeDefFilter;
					}
					virtual bool checkFilterAfter(CE::Hook::DynHook* hook) {
						return m_afterDefFilter;
					}

					virtual void serialize(Utils::BitStream& bt) {};
					virtual void deserialize(Utils::BitStream& bt) {};

					void setBeforeDefaultFilter(bool toggle) {
						m_beforeDefFilter = toggle;
					}

					void setAfterDefaultFilter(bool toggle) {
						m_afterDefFilter = toggle;
					}
				private:
					bool m_beforeDefFilter = false;
					bool m_afterDefFilter = false;
				};

				class Empty : public IFilter
				{
				public:
					Empty() {}

					Id getId() override {
						return Id::Empty;
					}

					bool checkFilterBefore(CE::Hook::DynHook* hook) override {
						return true;
					}

					bool checkFilterAfter(CE::Hook::DynHook* hook) override {
						return true;
					}
				};

				class Object : public IFilter
				{
				public:
					Object() = default;
					Object(void* addr)
						: m_addr(addr)
					{}

					Id getId() override {
						return Id::Object;
					}

					bool checkFilterBefore(CE::Hook::DynHook* hook) override {
						return hook->getArgumentValue<void*>(1) == m_addr;
					}

					void serialize(Utils::BitStream& bt)
					{
						Data data;
						data.m_addr = m_addr;
						bt.write(&data, sizeof(Data));
					}

					void deserialize(Utils::BitStream& bt)
					{
						Data data;
						bt.read(&data, sizeof(Data));
						m_addr = data.m_addr;
					}
				private:
					struct Data
					{
						void* m_addr;
					};

					void* m_addr = nullptr;
				};

				namespace Cmp
				{
					enum Operation
					{
						Eq,
						Neq,
						Lt,
						Le,
						Gt,
						Ge
					};

					template<typename T>
					static bool cmp(T op1, T op2, Operation operation)
					{
						switch (operation)
						{
						case Operation::Eq: return op1 == op2;
						case Operation::Neq: return op1 != op2;
						case Operation::Lt: return op1 < op2;
						case Operation::Le: return op1 <= op2;
						case Operation::Gt: return op1 > op2;
						case Operation::Ge: return op1 >= op2;
						}
						return false;
					}

					static bool cmp(uint64_t op1, uint64_t op2, Operation operation, CE::Type::Type* type)
					{
						using namespace CE::Type;
						if (type->getGroup() == CE::Type::Type::Simple) {
							switch (SystemType::GetBasicTypeOf(type))
							{
							case SystemType::Bool:
							case SystemType::Byte:
								return cmp<BYTE>(op1, op2, operation);
							case SystemType::Int8:
								return cmp<int8_t>(op1, op2, operation);
							case SystemType::Int16:
								return cmp<int16_t>(op1, op2, operation);
							case SystemType::Int32:
								return cmp<int32_t>(op1, op2, operation);
							case SystemType::Int64:
								return cmp<int64_t>(op1, op2, operation);
							case SystemType::UInt16:
							case SystemType::UInt32:
							case SystemType::UInt64:
								return cmp<uint64_t>(op1, op2, operation);
							case SystemType::Float:
								return cmp<float>(op1, op2, operation);
							case SystemType::Double:
								return cmp<double>(op1, op2, operation);
							}
						}
						return false;
					}

					class Argument : public IFilter
					{
					public:

						Argument() = default;
						Argument(int argId, uint64_t value, Operation operation)
							: m_argId(argId), m_value(value), m_operation(operation)
						{}

						Id getId() override {
							return Id::Argument;
						}

						bool checkFilterBefore(CE::Hook::DynHook* hook) override {
							using namespace CE::Type;

							auto function = (CE::Function::Function*)hook->getUserPtr();
							auto type = function->getSignature().getArgList()[m_argId - 1];
							return cmp(
								SystemType::GetNumberSetOf(type) == SystemType::Real ? hook->getXmmArgumentValue(m_argId) : hook->getArgumentValue(m_argId),
								m_value,
								m_operation
							);
						}

						template<typename T = uint64_t>
						void setValue(T value) {
							(T&)m_value = value;
						}

						void setOperation(Operation operation) {
							m_operation = operation;
						}

						void serialize(Utils::BitStream& bt)
						{
							Data data;
							data.m_argId = m_argId;
							data.m_value = m_value;
							data.m_operation = m_operation;
							bt.write(&data, sizeof(Data));
						}

						void deserialize(Utils::BitStream& bt)
						{
							Data data;
							bt.read(&data, sizeof(Data));
							m_argId = data.m_argId;
							m_value = data.m_value;
							m_operation = data.m_operation;
						}
					private:
						struct Data
						{
							int m_argId;
							uint64_t m_value;
							Operation m_operation;
						};
						int m_argId = 0;
						uint64_t m_value = 0;
						Operation m_operation = Operation::Eq;
					};

					class RetValue : public IFilter
					{
					public:
						RetValue() = default;
						RetValue(uint64_t value, Operation operation)
							: m_value(value), m_operation(operation)
						{}

						Id getId() override {
							return Id::ReturnValue;
						}

						bool checkFilterAfter(CE::Hook::DynHook* hook) override {
							using namespace CE::Type;
							
							auto function = (CE::Function::Function*)hook->getUserPtr();
							auto type = function->getSignature().getReturnType();
							return cmp(
								SystemType::GetNumberSetOf(type) == SystemType::Real ? hook->getXmmReturnValue() : hook->getReturnValue(),
								m_value,
								m_operation
							);
						}

						template<typename T = uint64_t>
						void setValue(T value) {
							(T&)m_value = value;
						}

						void setOperation(Operation operation) {
							m_operation = operation;
						}
					
						void serialize(Utils::BitStream& bt)
						{
							Data data;
							data.m_value = m_value;
							data.m_operation = m_operation;
							bt.write(&data, sizeof(Data));
						}

						void deserialize(Utils::BitStream& bt)
						{
							Data data;
							bt.read(&data, sizeof(Data));
							m_value = data.m_value;
							m_operation = data.m_operation;
						}
					private:
						struct Data
						{
							int m_argId;
							uint64_t m_value;
							Operation m_operation;
						};
						uint64_t m_value = 0;
						Operation m_operation = Operation::Eq;
					};
				};
			};

			struct TriggerState
			{
				bool m_beforeFilter = false;
			};

			class Trigger;
			class Hook
			{
			public:
				Hook(CE::Function::Function* func);

				inline std::list<Trigger*>& getTriggers() {
					return m_triggers;
				}

				inline CE::Hook::DynHook* getDynHook() {
					return &m_hook;
				}

				void addTrigger(Trigger* trigger) {
					m_triggers.push_back(trigger);
				}

				void removeTrigger(Trigger* trigger) {
					m_triggers.remove(trigger);
				}
			private:
				CE::Hook::DynHook m_hook;
				std::list<Trigger*> m_triggers;
			};

			class Trigger : public ITrigger
			{
			public:
				Trigger(int id, std::string name, std::string desc = "")
					: ITrigger(id, name, desc)
				{}

				Type getType() override {
					return Type::FunctionTrigger;
				}

				std::string getName() override {
					return "Function trigger";
				}

				std::string getDesc() override {
					return "Function trigger need for garbaging statistic and filtering function calls.";
				}

				void addFilter(Filter::IFilter* filter) {
					m_filters.push_back(filter);
				}

				void removeFilter(Filter::IFilter* filter) {
					m_filters.remove(filter);
				}

			public:
				bool checkFilterBefore(CE::Hook::DynHook* hook) {
					for (auto& filter : m_filters) {
						if (filter->checkFilterBefore(hook)) {
							return true;
						}
					}
					return false;
				}

				bool checkFilterAfter(CE::Hook::DynHook* hook) {
					for (auto& filter : m_filters) {
						if (filter->checkFilterAfter(hook)) {
							return true;
						}
					}
					return false;
				}

				bool actionBefore(CE::Hook::DynHook* hook) {
					bool sendStat = false;
					bool notExecute = false;
					if (checkFilterBefore(hook)) {
						notExecute = m_notExecute;
						hook->getUserData<TriggerState>().m_beforeFilter = true;
						sendStat = true;
					}

					if (sendStat) {
						if (m_statArgManager != nullptr) {
							m_statArgManager->add(this, hook);
						}
					}
					return !notExecute;
				}

				void actionAfter(CE::Hook::DynHook* hook) {
					bool sendStat = hook->getUserData<TriggerState>().m_beforeFilter;
					if (checkFilterAfter(hook)) {
						sendStat = true;
					}

					if (sendStat) {
						if (m_statRetManager != nullptr) {
							m_statRetManager->add(this, hook);
						}
					}
				}

				void setStatArgManager(Stat::Function::Args::Manager* manager) {
					m_statArgManager = manager;
				}

				void setStatRetManager(Stat::Function::Ret::Manager* manager) {
					m_statRetManager = manager;
				}

				void setNotExecute(bool toggle) {
					m_notExecute = toggle;
				}

				auto& getFilters() {
					return m_filters;
				}
			private:
				Stat::Function::Args::Manager* m_statArgManager = nullptr;
				Stat::Function::Ret::Manager* m_statRetManager = nullptr;
				std::list<Filter::IFilter*> m_filters;
				bool m_notExecute = false;
			};

			static bool callback_before(CE::Hook::DynHook* hook)
			{
				auto func = (CE::Function::Function*)hook->getUserPtr();
				bool exectute = true;
				for (auto trigger : func->getHook()->getTriggers()) {
					exectute &= trigger->actionBefore(hook);
				}

			/*	auto value1 = hook->getArgumentValue<uint64_t>(5);
				auto value2 = hook->getXmmArgumentValue<float>(2);
				auto value3 = hook->getXmmArgumentValue<float>(3);
				auto value4 = hook->getXmmArgumentValue<float>(4);*/

				return exectute;
			}

			static void callback_after(CE::Hook::DynHook* hook)
			{
				auto func = (CE::Function::Function*)hook->getUserPtr();
				for (auto trigger : func->getHook()->getTriggers()) {
					trigger->actionAfter(hook);
				}
				//hook->setReturnValue(11);
			}
		};
	};



	class TriggerManager : public IManager
	{
	public:
		using TriggerDict = std::map<int, Trigger::ITrigger*>;

		TriggerManager(SDA* sda)
			: IManager(sda)
		{}

		void saveTrigger(Trigger::ITrigger* trigger) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();

			{
				SQLite::Statement query(db, "REPLACE INTO sda_triggers(id, type, name, desc) VALUES(?1, ?2, ?3, ?4)");
				query.bind(1, trigger->getId());
				query.bind(2, trigger->getType());
				query.bind(3, trigger->getName());
				query.bind(4, trigger->getDesc());
				query.exec();
			}

			if (trigger->getType() == Trigger::FunctionTrigger) {
				saveFiltersForFuncTrigger((Trigger::Function::Trigger*)trigger);
			}
		}

		void saveFiltersForFuncTrigger(Trigger::Function::Trigger* trigger) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_func_trigger_filters WHERE trigger_id=?1");
				query.bind(1, trigger->getId());
				query.exec();
			}

			{
				for (const auto& filter : trigger->getFilters()) {
					Utils::BitStream bt;
					filter->serialize(bt);

					SQLite::Statement query(db, "INSERT INTO sda_func_trigger_filters (trigger_id, filter_id, data) VALUES(?1, ?2, ?3)");
					query.bind(1, trigger->getId());
					query.bind(2, (int)filter->getId());
					query.bind(3, bt.getData(), bt.getSize());
					query.exec();
				}
			}

			transaction.commit();
		}

		void loadFiltersForFuncTrigger(Trigger::Function::Trigger* trigger)
		{
			using namespace SQLite;
			using namespace Trigger::Function::Filter;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT filter_id,data FROM sda_func_trigger_filters WHERE trigger_id=?1");
			query.bind(1, trigger->getId());

			while (query.executeStep())
			{
				IFilter* filter = nullptr;
				auto filter_id = (Id)(int)query.getColumn("filter_id");

				switch (filter_id)
				{
				case Id::Empty:
					filter = new Empty;
					break;
				case Id::Object:
					filter = new Object;
					break;
				case Id::Argument:
					filter = new Cmp::Argument;
					break;
				case Id::ReturnValue:
					filter = new Cmp::RetValue;
					break;
				}

				Utils::BitStream bt;
				bt.write(query.getColumn("data").getBlob(), query.getColumn("data").getBytes());
				bt.resetPointer();
				filter->deserialize(bt);

				trigger->addFilter(filter);
			}
		}

		void removeTrigger(Trigger::ITrigger* trigger) {
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "DELETE FROM sda_triggers WHERE id=?1");
			query.bind(1, trigger->getId());
			query.exec();

			auto it = m_triggers.find(trigger->getId());
			if (it != m_triggers.end()) {
				m_triggers.erase(it);
			}
		}

		int getNewId() {
			int id = 1;
			while (m_triggers.find(id) != m_triggers.end())
				id++;
			return id;
		}

		Trigger::Function::Trigger* createFunctionTrigger(std::string name, std::string desc = "") {
			int id = getNewId();
			auto trigger = new Trigger::Function::Trigger(id, name, desc);
			m_triggers[id] = trigger;
			return trigger;
		}

		void loadTriggers()
		{
			using namespace SQLite;

			SQLite::Database& db = getSDA()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_triggers");

			while (query.executeStep())
			{
				Trigger::ITrigger* trigger = nullptr;

				int type = query.getColumn("type");
				switch ((Trigger::Type)type)
				{
				case Trigger::FunctionTrigger:
					trigger = new Trigger::Function::Trigger(
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
					loadFiltersForFuncTrigger((Trigger::Function::Trigger*)trigger);
					break;
				}

				if (trigger != nullptr) {
					addTrigger(trigger);
				}
			}
		}

		void addTrigger(Trigger::ITrigger* trigger) {
			m_triggers.insert(std::make_pair(trigger->getId(), trigger));
		}

		inline Trigger::ITrigger* getTriggerById(int trigger_id) {
			if (m_triggers.find(trigger_id) == m_triggers.end())
				return nullptr;
			return m_triggers[trigger_id];
		}
	private:
		TriggerDict m_triggers;
	};

	namespace Ghidra
	{
		using namespace ghidra;

		class DataTypeManager;
		class FunctionManager;

		class Client
		{
		public:
			friend class DataTypeManager;
			friend class FunctionManager;

			DataTypeManager* m_dataTypeManager = nullptr;
			FunctionManager* m_functionManager = nullptr;

			Client(SDA* sda)
				: m_sda(sda)
			{
				m_socket = std::shared_ptr<TTransport>(new TSocket("localhost", m_port));
				m_transport = std::shared_ptr<TTransport>(new TBufferedTransport(m_socket));
				m_protocol = std::shared_ptr<TProtocol>(new TBinaryProtocol(m_transport));
				initManagers();
			}

			void initManagers();

			SDA* getSDA() {
				return m_sda;
			}
		private:
			SDA* m_sda = nullptr;

			std::shared_ptr<TTransport> m_socket;
			std::shared_ptr<TTransport> m_transport;
			std::shared_ptr<TProtocol> m_protocol;
			int m_port = 9090;
		};

		class IManager
		{
		public:
			IManager(Client* client)
				: m_client(client)
			{}
		protected:
			Client* getClient() {
				return m_client;
			}
		private:
			Client* m_client;
		};

		class Transport
		{
		public:
			Transport(std::shared_ptr<TTransport> transport)
				: m_transport(transport)
			{
				m_transport->open();
			}

			~Transport()
			{
				m_transport->close();
			}
		private:
			std::shared_ptr<TTransport> m_transport;
		};

		class DataTypeManager : public IManager
		{
		public:
			using HashMap = std::map<datatype::Id, datatype::Hash>; //todo: 1) по lastUpdatedDate  2) сделать глобальным и изменять его при изменении типов

			DataTypeManager(TypeManager* typeManager, Client* client)
				:
				m_typeManager(typeManager),
				IManager(client),
				m_client(std::shared_ptr<TMultiplexedProtocol>(new TMultiplexedProtocol(getClient()->m_protocol, "DataTypeManager")))
			{}

			datatype::Id getId(Type::Type* type, bool ghidraType = true) {
				Utils::ObjectHash objHash;
				if (ghidraType && type->isSystem()) {
					objHash.addValue(m_typeManager->getGhidraName(type));
				}
				else {
					objHash.addValue(type->getName());
				}
				return objHash.getHash();
			}

			shared::STypeUnit getTypeUnit(Type::Type* type) {
				shared::STypeUnit typeUnitDesc;
				typeUnitDesc.__set_typeId(getId(type));
				typeUnitDesc.__set_pointerLvl(type->getPointerLvl());
				typeUnitDesc.__set_arraySize(type->getArraySize());
				return typeUnitDesc;
			}

			Type::Type* getType(const shared::STypeUnit& typeUnitDesc) {
				return m_typeManager->getType(findTypeById(typeUnitDesc.typeId), typeUnitDesc.pointerLvl, typeUnitDesc.arraySize);
			}

			Type::Type* findTypeById(datatype::Id id, bool returnDefType = true) {
				for (auto& it : m_typeManager->getTypes()) {
					if (getId(it.second, false) == id) {
						return it.second;
					}
				}
				return returnDefType ? m_typeManager->getDefaultType() : nullptr;
			}

			datatype::SDataType buildDescToRemove(Type::Type* type) {
				datatype::SDataType typeDesc;
				typeDesc.__set_id(getId(type));
				typeDesc.__set_size(0);
				return typeDesc;
			}

			datatype::SDataType buildTypeDesc(Type::UserType* type) {
				datatype::SDataType typeDesc;
				typeDesc.__set_id(getId(type));
				typeDesc.__set_group((datatype::DataTypeGroup::type)type->getGroup());
				typeDesc.__set_size(type->getSize());
				typeDesc.__set_name(type->getName());
				typeDesc.__set_desc(type->getDesc());
				return typeDesc;
			}

			datatype::SDataTypeTypedef buildDesc(Type::Typedef* Typedef) {
				datatype::SDataTypeTypedef typedefDesc;
				typedefDesc.__set_type(buildTypeDesc(Typedef));
				typedefDesc.refType.__set_typeId(Typedef->getRefType()->getId());
				typedefDesc.refType.__set_pointerLvl(Typedef->getRefType()->getPointerLvl());
				typedefDesc.refType.__set_arraySize(Typedef->getRefType()->getArraySize());
				return typedefDesc;
			}

			datatype::SDataTypeEnum buildDesc(Type::Enum* enumeration) {
				datatype::SDataTypeEnum enumDesc;
				enumDesc.__set_type(buildTypeDesc(enumeration));
				for (auto& field : enumeration->getFieldDict()) {
					datatype::SDataTypeEnumField enumFieldDesc;
					enumFieldDesc.__set_name(field.second);
					enumFieldDesc.__set_value(field.first);
					enumDesc.fields.push_back(enumFieldDesc);
				}
				return enumDesc;
			}

			datatype::SDataTypeStructure buildDesc(Type::Class* Class) {
				datatype::SDataTypeStructure structDesc;
				structDesc.__set_type(buildTypeDesc(Class));

				int curOffset = 0;
				if (Class->hasVTable()) {
					datatype::SDataTypeStructureField structFieldDesc;
					structFieldDesc.__set_name("vtable");
					structFieldDesc.__set_offset(0);
					Type::Void vtableType;
					structFieldDesc.type.__set_typeId(getId(&vtableType));
					structFieldDesc.type.__set_pointerLvl(1);
					structFieldDesc.type.__set_arraySize(0);
					structFieldDesc.__set_comment("{vtable}");
					structDesc.fields.push_back(structFieldDesc);
					curOffset = 0x8;
				}

				if (Class->getBaseClass() != nullptr) {
					Type::Class* baseClass = Class->getBaseClass();
					datatype::SDataTypeStructureField structFieldDesc;
					structFieldDesc.__set_name(baseClass->getName());
					structFieldDesc.__set_offset(curOffset);
					structFieldDesc.type.__set_typeId(getId(baseClass));
					structFieldDesc.type.__set_pointerLvl(0);
					structFieldDesc.type.__set_arraySize(0);
					structFieldDesc.__set_comment("{base class}");
					structDesc.fields.push_back(structFieldDesc);
					curOffset += baseClass->getSizeWithoutVTable();
				}

				for (auto& it : Class->getFieldDict()) {
					auto& field = it.second;
					datatype::SDataTypeStructureField structFieldDesc;
					structFieldDesc.__set_name(field.getName());
					structFieldDesc.__set_offset(curOffset + it.first);
					structFieldDesc.type.__set_typeId(getId(field.getType()));
					structFieldDesc.type.__set_pointerLvl(field.getType()->getPointerLvl());
					structFieldDesc.type.__set_arraySize(field.getType()->getArraySize());
					structFieldDesc.__set_comment(field.getDesc());
					structDesc.fields.push_back(structFieldDesc);
				}

				return structDesc;
			}

			void change(Type::UserType* type, const datatype::SDataType& typeDesc) {
				type->setName(typeDesc.name);
				if (typeDesc.desc != "{pull}") {
					type->setDesc(typeDesc.desc);
				}
			}

			void change(Type::Typedef* Typedef, const datatype::SDataTypeTypedef& typdefDesc) {
				auto ref_type = findTypeById(typdefDesc.refType.typeId);
				if (ref_type != nullptr) {
					Typedef->setRefType(getType(typdefDesc.refType));
				}
			}

			void change(Type::Enum* enumeration, const datatype::SDataTypeEnum& enumDesc) {
				enumeration->setSize(enumDesc.type.size);
				enumeration->deleteAll();
				for (auto& field : enumDesc.fields) {
					enumeration->addField(field.name, field.value);
				}
			}

			void change(Type::Class* Class, const datatype::SDataTypeStructure& structDesc) {
				int curField = 0;
				if (structDesc.fields.size() >= 1) {
					auto& vtable = structDesc.fields[curField];
					if (vtable.type.pointerLvl == 1 && vtable.type.arraySize == 0) {
						if (vtable.comment.find("{vtable}") != std::string::npos) {
							//Class->setVtable();
							curField++;
						}
					}
				}

				if (structDesc.fields.size() >= 2) {
					auto& baseClass = structDesc.fields[curField];
					if (baseClass.type.pointerLvl == 0 && baseClass.type.arraySize == 0) {
						if (baseClass.comment.find("{base class}") != std::string::npos) {
							auto type = findTypeById(baseClass.type.typeId);
							if (type->getGroup() == Type::Type::Class) {
								Class->setBaseClass((Type::Class*)type);
								curField++;
							}
						}
					}
				}

				for (int i = curField; i < structDesc.fields.size(); i++) {
					auto& field = structDesc.fields[i];
					Class->addField(field.offset, field.name, getType(field.type), field.comment);
				}
			}

			void push(const std::vector<datatype::SDataType>& dataTypeDescBuffer) {
				Transport tr(getClient()->m_transport);
				m_client.push(dataTypeDescBuffer);
			}

			void push(const std::vector<datatype::SDataTypeTypedef>& dataTypedefDescBuffer) {
				Transport tr(getClient()->m_transport);
				m_client.pushTypedefs(dataTypedefDescBuffer);
			}

			void push(const std::vector<datatype::SDataTypeEnum>& dataEnumDescBuffer) {
				Transport tr(getClient()->m_transport);
				m_client.pushEnums(dataEnumDescBuffer);
			}

			void push(const std::vector<datatype::SDataTypeStructure>& dataStructDescBuffer) {
				Transport tr(getClient()->m_transport);
				m_client.pushStructures(dataStructDescBuffer);
			}

			std::vector<datatype::SDataTypeBase> pullAll() {
				Transport tr(getClient()->m_transport);
				std::vector<datatype::SDataTypeBase> result;
				m_client.pull(result);
				return result;
			}

			std::vector<datatype::SDataTypeTypedef> pullTypedefs(const HashMap& hashmap) {
				Transport tr(getClient()->m_transport);
				std::vector<datatype::SDataTypeTypedef> result;
				m_client.pullTypedefs(result, hashmap);
				return result;
			}

			std::vector<datatype::SDataTypeEnum> pullEnums(const HashMap& hashmap) {
				Transport tr(getClient()->m_transport);
				std::vector<datatype::SDataTypeEnum> result;
				m_client.pullEnums(result, hashmap);
				return result;
			}

			std::vector<datatype::SDataTypeStructure> pullStructures(const HashMap& hashmap) {
				Transport tr(getClient()->m_transport);
				std::vector<datatype::SDataTypeStructure> result;
				m_client.pullStructures(result, hashmap);
				return result;
			}

			Type::Type* changeOrCreate(const datatype::SDataType& dataType) {
				Type::Type* type = findTypeById(dataType.id, false);
				if (type == nullptr) {
					switch (dataType.group)
					{
					case datatype::DataTypeGroup::Typedef:
						type = m_typeManager->createTypedef(m_typeManager->getDefaultType(), dataType.name, dataType.desc);
						break;
					case datatype::DataTypeGroup::Enum:
						type = m_typeManager->createEnum(dataType.name, dataType.desc);
						break;
					case datatype::DataTypeGroup::Structure:
						type = m_typeManager->createClass(dataType.name, dataType.desc);
						break;
					}
				}
				else {
					if (type->isUserDefined() && (int)type->getGroup() == (int)dataType.group) {
						change((Type::UserType*)type, dataType);
					}
					else {
						type = nullptr;
					}
				}
				return type;
			}

			Type::Typedef* changeOrCreate(const datatype::SDataTypeTypedef& Typedef) {
				auto type = (Type::Typedef*)changeOrCreate(Typedef.type);
				if (type == nullptr)
					return nullptr;
				change(type, Typedef);
				return type;
			}

			Type::Enum* changeOrCreate(const datatype::SDataTypeEnum& enumeration) {
				auto type = (Type::Enum*)changeOrCreate(enumeration.type);
				if (type == nullptr)
					return nullptr;
				change(type, enumeration);
				return type;
			}

			Type::Class* changeOrCreate(const datatype::SDataTypeStructure& structure) {
				auto type = (Type::Class*)changeOrCreate(structure.type);
				if (type == nullptr)
					return nullptr;
				change(type, structure);
				return type;
			}

			void updateAll() {
				auto types = pullAll();
				for (auto type : types) {
					datatype::SDataType dataType;
					dataType.__set_id(type.id);
					dataType.__set_group(type.group);
					dataType.__set_name(type.name);
					dataType.__set_desc("{pull}");
					changeOrCreate(dataType);
				}
			}
			//TODO: исправить хеширование
			void updateTypedefs(HashMap hashmap) {
				auto typedefs = pullTypedefs(hashmap);
				for (auto Typedef : typedefs) {
					changeOrCreate(Typedef);
				}
			}

			void updateEnums(HashMap hashmap) {
				auto enumerations = pullEnums(hashmap);
				for (auto enumeration : enumerations) {
					changeOrCreate(enumeration);
				}
			}

			void updateStructures(HashMap hashmap) {
				auto structures = pullStructures(hashmap);
				for (auto structure : structures) {
					changeOrCreate(structure);
				}
			}

			Utils::ObjectHash getHash(const datatype::SDataType& typeDesc) {
				Utils::ObjectHash hash;
				hash.addValue(typeDesc.name);
				hash.addValue(typeDesc.desc);
				return hash;
			}

			Utils::ObjectHash getHash(const datatype::SDataTypeTypedef& typedefDesc) {
				Utils::ObjectHash hash = getHash(typedefDesc.type);
				hash.addValue(typedefDesc.refType.typeId);
				hash.addValue(typedefDesc.refType.pointerLvl);
				hash.addValue(typedefDesc.refType.arraySize);
				return hash;
			}

			Utils::ObjectHash getHash(const datatype::SDataTypeStructure& structDesc) {
				Utils::ObjectHash hash = getHash(structDesc.type);
				for (auto& field : structDesc.fields) {
					Utils::ObjectHash fieldHash;
					fieldHash.addValue(field.offset);
					fieldHash.addValue(field.name);
					fieldHash.addValue(field.comment);
					fieldHash.addValue((int64_t)field.type.typeId);
					fieldHash.addValue(field.type.pointerLvl);
					fieldHash.addValue(field.type.arraySize);
					hash.add(fieldHash);
				}
				return hash;
			}

			Utils::ObjectHash getHash(const datatype::SDataTypeEnum& enumDesc) {
				Utils::ObjectHash hash = getHash(enumDesc.type);
				for (auto& field : enumDesc.fields) {
					Utils::ObjectHash fieldHash;
					fieldHash.addValue(field.name);
					fieldHash.addValue(field.value);
					hash.add(fieldHash);
				}
				return hash;
			}

			datatype::Hash getHash(Type::Type* type) {
				switch (type->getGroup())
				{
				case Type::Type::Typedef:
					return getHash(buildDesc((Type::Typedef*)type)).getHash();
				case Type::Type::Enum:
					return getHash(buildDesc((Type::Enum*)type)).getHash();
				case Type::Type::Class:
					return getHash(buildDesc((Type::Class*)type)).getHash();
				}
				return 0;
			}

			HashMap generateHashMap() {
				HashMap hashmap;
				for (auto& it : m_typeManager->getTypes()) {
					if (it.second->isUserDefined()) {
						auto type = (Type::UserType*)it.second;
						if (type->isGhidraUnit()) {
							hashmap.insert(std::make_pair(getId(type), getHash(type)));
						}
					}
				}

				return hashmap;
			}
		private:
			TypeManager* m_typeManager;
			datatype::DataTypeManagerServiceClient m_client;
		};

		class FunctionManager : public IManager
		{
		public:
			using HashMap = std::map<function::Id, function::Hash>;

			FunctionManager(CE::FunctionManager* functionManager, Client* client)
				:
				m_functionManager(functionManager),
				IManager(client),
				m_client(std::shared_ptr<TMultiplexedProtocol>(new TMultiplexedProtocol(getClient()->m_protocol, "FunctionManager")))
			{}

			function::Id getId(Function::Function* function) {
				/*Utils::ObjectHash objHash;
				objHash.addValue(m_functionManager->getFunctionOffset(function));
				return objHash.getHash();*/
				return m_functionManager->getFunctionOffset(function);
			}

			Function::Function* findFunctionById(function::Id id, bool returnDefType = true) {
				for (auto& it : m_functionManager->getFunctions()) {
					if (getId(it.second) == id) {
						return it.second;
					}
				}
				return returnDefType ? m_functionManager->getDefaultFunction() : nullptr;
			}

			function::SFunction buildDescToRemove(Function::Function* function) {
				function::SFunction funcDesc;
				funcDesc.__set_id(getId(function));
				funcDesc.__set_name("{remove}");
				return funcDesc;
			}

			function::SFunction buildDesc(Function::Function* function) {
				function::SFunction funcDesc;
				funcDesc.__set_id(getId(function));

				auto spliter = function->getName().find("::");
				if (spliter != std::string::npos) {
					std::string funcName = function->getName();
					funcName[spliter] = '_';
					funcName[spliter + 1] = '_';
					funcDesc.__set_name(funcName);
				}
				else {
					funcDesc.__set_name(function->getName());
				}

				funcDesc.__set_comment(function->getDesc());

				auto& signature = function->getSignature();
				funcDesc.signature.__set_returnType(
					getClient()->m_dataTypeManager->getTypeUnit(signature.getReturnType())
				);
				for (int i = 0; i < signature.getArgList().size(); i++) {
					auto argType = signature.getArgList()[i];
					auto argName = function->getArgNameList()[i];
					funcDesc.signature.arguments.push_back(getClient()->m_dataTypeManager->getTypeUnit(argType));
					funcDesc.argumentNames.push_back(argName);
				}

				for (auto& range : function->getRangeList()) {
					function::SFunctionRange rangeDesc;
					rangeDesc.__set_minOffset(getClient()->getSDA()->toRelAddr(range.getMinAddress()));
					rangeDesc.__set_maxOffset(getClient()->getSDA()->toRelAddr(range.getMaxAddress()));
					funcDesc.ranges.push_back(rangeDesc);
				}

				return funcDesc;
			}

			void push(const std::vector<function::SFunction>& functionDescBuffer) {
				Transport tr(getClient()->m_transport);
				m_client.push(functionDescBuffer);
			}

			std::vector<function::SFunction> pull(const HashMap& hashmap) {
				Transport tr(getClient()->m_transport);
				std::vector<function::SFunction> result;
				m_client.pull(result, hashmap);
				return result;
			}

			Function::Function::RangeList getFunctionRanges(const std::vector<function::SFunctionRange>& rangeDescs) {
				Function::Function::RangeList ranges;
				for (auto& range : rangeDescs) {
					ranges.push_back(Function::Function::Range(
						getClient()->getSDA()->toAbsAddr(range.minOffset),
						getClient()->getSDA()->toAbsAddr(range.maxOffset)
					));
				}
				return ranges;
			}

			void change(Function::Function* function, const function::SFunction& funcDesc) {
				function->setName(funcDesc.name);
				function->setDesc(funcDesc.comment);

				auto& signature = function->getSignature();
				signature.setReturnType(
					getClient()->m_dataTypeManager->getType(funcDesc.signature.returnType)
				);
				
				function->deleteAllArguments();
				auto& args = funcDesc.signature.arguments;
				for (int i = 0; i < args.size(); i++) {
					function->addArgument(getClient()->m_dataTypeManager->getType(args[i]), funcDesc.argumentNames[i]);
				}

				function->getRangeList().clear();
				function->getRangeList() = getFunctionRanges(funcDesc.ranges);
			}

			Function::Function* changeOrCreate(const function::SFunction& funcDesc) {
				Function::Function* function = findFunctionById(funcDesc.id, false);
				if (function == nullptr) {
					function = m_functionManager->createFunction(getClient()->getSDA()->toAbsAddr(funcDesc.ranges[0].minOffset), {}, "", "");
				}

				change(function, funcDesc);
				return function;
			}

			void update(HashMap hashmap) {
				auto functions = pull(hashmap);
				for (auto function : functions) {
					changeOrCreate(function);
				}
			}

			Utils::ObjectHash getHash(const function::SFunction& funcDesc) {
				Utils::ObjectHash hash;
				hash.addValue(funcDesc.name);
				hash.addValue(funcDesc.comment);
				
				auto& args = funcDesc.signature.arguments;
				for (int i = 0; i < args.size(); i++) {
					Utils::ObjectHash argHash;
					argHash.addValue(funcDesc.argumentNames[i]);
					argHash.addValue(args[i].typeId);
					argHash.addValue(args[i].pointerLvl);
					argHash.addValue(args[i].arraySize);
					hash.join(argHash);
				}

				for (auto& range : funcDesc.ranges) {
					Utils::ObjectHash rangeHash;
					rangeHash.addValue(range.minOffset);
					rangeHash.addValue(range.maxOffset);
					hash.add(rangeHash);
				}
				return hash;
			}

			function::Hash getHash(Function::Function* function) {
				return getHash(buildDesc(function)).getHash();
			}

			HashMap generateHashMap() {
				HashMap hashmap;
				for (auto& it : m_functionManager->getFunctions()) {
					auto function = it.second;
					if (function->isGhidraUnit()) {
						hashmap.insert(std::make_pair(getId(function), getHash(function)));
					}
				}

				return hashmap;
			}
		private:
			CE::FunctionManager* m_functionManager;
			function::FunctionManagerServiceClient m_client;
		};
	};
};