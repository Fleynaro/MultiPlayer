#pragma once
#include "AbstractType.h"
#include "Utility/Generic.h"

namespace CE
{
	namespace Type
	{
		//MY TODO: ������� ��� ��, ��� � � GUI: canBeRemoved
		/*
			1) canBeRemoved: ���� ���������� ��� true, � ��� false. ��� true �������� �������� ���������� ������������� ����� ����
			2) ������� � ����������� �� ���������: ���� ��� ����� �������� �� �������(Pointer), ��� �������� ������ ������, � ������� ���
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