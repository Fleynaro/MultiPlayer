#pragma once
#include "AbstractType.h"
#include "Utility/Generic.h"

namespace CE
{
	namespace Type
	{
		//MY TODO: сделать так же, как и в GUI: canBeRemoved
		/*
			1) canBeRemoved: надо заботиться где true, а где false. при true остается проблема нескольких собственников этого типа
			2) удалять в зависимости от контекста: один тип может зависить от другого(Pointer), где родитель должен удален, а потомок нет
		*/
		class Pointer : public Type
		{
		public:
			Pointer(Type* type)
				: m_type(type)
			{
				if (type->isArray())
					throw std::logic_error("Pointer cannot point at an array.");
				m_type->addOwner();
			}

			~Pointer() {
				m_type->free();
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

			std::string getDesc() override {
				return getType()->getDesc();
			}

			std::string getDisplayName() override {
				return getType()->getDisplayName() + "*";
			}

			int getSize() override {
				return 8;
			}

			std::string getViewValue(void* addr) override {
				return "(" + getDisplayName() + ")0x" + Generic::String::NumberToHex(*(uint64_t*)addr);
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
	};
};