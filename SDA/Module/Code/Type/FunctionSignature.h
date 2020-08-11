#pragma once
#include "UserType.h"
#include "../Symbol/FuncParameterSymbol.h"

namespace CE
{
	namespace DataType
	{
		class Storage {
		public:
			enum StorageType {
				STORAGE_REGISTER,
				STORAGE_STACK,
				STORAGE_GLOBAL
			};

			Storage(int index, StorageType storageType, int registerId, int offset)
				: m_index(index), m_storageType(storageType), m_registerId(registerId), m_offset(offset)
			{}

			int getIndex() {
				return m_index;
			}

			StorageType getType() {
				return m_storageType;
			}

			int getRegisterId() {
				return m_registerId;
			}

			int getOffset() {
				return m_offset;
			}
		private:
			int m_index;
			StorageType m_storageType;
			int m_registerId;
			int m_offset;
		};

		class Signature : public UserType
		{
		public:
			enum CallingConvetion {
				FASTCALL
			};

			Signature(TypeManager* typeManager, const std::string& name, const std::string& comment = "", CallingConvetion callingConvetion = FASTCALL);
			
			Group getGroup() override;

			int getSize() override;

			CallingConvetion getCallingConvetion() {
				return m_callingConvetion;
			}

			std::list<Storage*>& getCustomStorages() {
				return m_customStorages;
			}

			std::string getSigName();

			void setReturnType(DataTypePtr returnType);

			DataTypePtr getReturnType();

			std::vector<Symbol::FuncParameterSymbol*>& getParameters();

			void addParameter(Symbol::FuncParameterSymbol* symbol);

			void addParameter(const std::string& name, DataTypePtr dataType, const std::string& comment = "");

			void removeLastParameter();

			void deleteAllParameters();

		private:
			CallingConvetion m_callingConvetion;
			std::list<Storage*> m_customStorages;
			std::vector<Symbol::FuncParameterSymbol*> m_parameters;
			DataTypePtr m_returnType;
		};
	};
};