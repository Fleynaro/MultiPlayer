#pragma once
#include "AbstractType.h"

namespace CE
{
	namespace DataType
	{
		class Unit : public Type
		{
		public:
			Unit(DataType::Type* type, std::list<int> levels = {});

			Group getGroup() override;

			bool isUserDefined() override;

			bool isFloatingPoint();

			int getPointerLvl();

			bool isArray();

			bool isPointer();

			std::list<int> getPointerLevels();

			void addPointerLevelInFront(int size = 1);

			void removePointerLevelOutOfFront();

			bool isString();

			bool equal(DataType::Unit* typeUnit);

			int getPriority();

			int getConversionPriority();

			const std::string getName() override;

			const std::string getComment() override;

			void setName(const std::string& name) override;

			void setComment(const std::string& comment) override;

			std::string getDisplayName() override;

			int getSize() override;

			std::string getViewValue(void* addr) override;

			DataType::Type* getType();
			
			DB::Id getId() override;

			void setId(DB::Id id) override;

			DB::IMapper* getMapper() override;

			void setMapper(DB::IMapper* mapper) override;

			static bool EqualPointerLvls(const std::list<int>& ptrList1, const std::list<int>& ptrList2);
		private:
			DataType::Type* m_type;
			std::list<int> m_levels;
		};
	};

	using DataTypePtr = std::shared_ptr<DataType::Unit>;

	namespace DataType
	{
		DataTypePtr GetUnit(DataType::Type* type, const std::list<int>& levels_list);
		DataTypePtr GetUnit(DataType::Type* type, const std::string& levels = "");
		std::string GetPointerLevelStr(DataTypePtr type);
		std::list<int> ParsePointerLevelsStr(const std::string& str);
		DataTypePtr CloneUnit(DataTypePtr dataType);
	};
};