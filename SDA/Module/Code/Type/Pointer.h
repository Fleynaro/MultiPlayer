#pragma once
#include "AbstractType.h"
#include "Utility/Generic.h"

namespace CE
{
	namespace DataType
	{
		//MY TODO: ������� ��� ��, ��� � � GUI: canBeRemoved
		/*
			1) canBeRemoved: ���� ���������� ��� true, � ��� false. ��� true �������� �������� ���������� ������������� ����� ����
			2) ������� � ����������� �� ���������: ���� ��� ����� �������� �� �������(Pointer), ��� �������� ������ ������, � ������� ���
		*/
		class Pointer : public Type
		{
		public:
			Pointer(Type* type);

			~Pointer();

			DB::Id getId() override;

			void setId(DB::Id id) override;

			Group getGroup() override;

			bool isUserDefined() override;

			std::string getName() override;

			std::string getDesc() override;

			std::string getDisplayName() override;

			int getSize() override;

			std::string getViewValue(void* addr) override;

			Type* getType();
			
			int getPointerLvl() override;

			int getArraySize() override;

			DB::Id getId() override;

			void setId(DB::Id id) override;

			DB::AbstractMapper* getMapper() override;

			void setMapper(DB::AbstractMapper* mapper) override;
		private:
			Type* m_type;
		};
	};
};