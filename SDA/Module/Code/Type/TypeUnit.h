#pragma once
#include "AbstractType.h"

namespace CE
{
	namespace DataType
	{
		class Unit : public Type
		{
		public:
			Unit(DataType::Type* type, std::vector<int> levels = {});

			Group getGroup() override;

			bool isUserDefined() override;

			int getPointerLvl();

			bool isPointer();

			std::vector<int> getPointerLevels();

			bool isString();

			std::string getName() override;

			std::string getDesc() override;

			std::string getDisplayName() override;

			int getSize() override;

			std::string getViewValue(void* addr) override;

			DataType::Type* getType();
			
			DB::Id getId() override;

			void setId(DB::Id id) override;

			DB::IMapper* getMapper() override;

			void setMapper(DB::IMapper* mapper) override;
		private:
			DataType::Type* m_type;
			std::vector<int> m_levels;
		};
	};

	using DataTypePtr = std::shared_ptr<DataType::Unit>;

	namespace DataType
	{
		DataTypePtr GetUnit(DataType::Type* type, const std::string& levels = "");
		std::string GetPointerLevelStr(DataTypePtr type);
		std::vector<int> ParsePointerLevelsStr(const std::string& str);
	};
};