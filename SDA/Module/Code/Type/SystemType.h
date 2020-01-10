#pragma once
#include "AbstractType.h"

namespace CE
{
	namespace Type
	{
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
	};
};