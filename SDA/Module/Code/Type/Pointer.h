#pragma once
#include "AbstractType.h"
#include "Utility/Generic.h"

namespace CE
{
	namespace DataType
	{
		//MY TODO: сделать так же, как и в GUI: canBeRemoved
		/*
			1) canBeRemoved: надо заботиться где true, а где false. при true остается проблема нескольких собственников этого типа
			2) удалять в зависимости от контекста: один тип может зависить от другого(Pointer), где родитель должен удален, а потомок нет
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