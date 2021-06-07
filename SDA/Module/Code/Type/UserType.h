#pragma once
#include "TypeUnit.h"

namespace CE
{
	namespace DataType
	{
		class UserType : public Type, public Ghidra::Object
		{
		public:
			UserType(const std::string& name, const std::string& comment = "")
				: Type(name, comment)
			{}

			bool isUserDefined() override;

			std::string getDisplayName() override;

			Ghidra::Id getGhidraId() override;

			DB::Id getId() override;

			void setId(DB::Id id) override;

			DB::IMapper* getMapper() override;

			void setMapper(DB::IMapper* mapper) override;
		private:
			DB::Id m_id;
			DB::IMapper* m_mapper = nullptr;
		};
	};
};