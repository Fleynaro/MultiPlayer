#pragma once
#include "AbstractManager.h"
#include <Manager/TypeManager.h>

namespace CE
{
	namespace Ghidra
	{
		class DataTypeManager : public AbstractManager
		{
		public:
			using HashMap = std::map<datatype::Id, datatype::Hash>; //MY TODO: 1) по lastUpdatedDate  2) сделать глобальным и изменять его при изменении типов

			DataTypeManager(TypeManager* typeManager, Client* client)
				:
				m_typeManager(typeManager),
				AbstractManager(client),
				m_client(std::shared_ptr<TMultiplexedProtocol>(new TMultiplexedProtocol(getClient()->m_protocol, "DataTypeManager")))
			{}

			datatype::Id getId(DataType::Type* type, bool ghidraType = true) {
				ObjectHash objHash;
				if (ghidraType && type->isSystem()) {
					objHash.addValue(m_typeManager->getGhidraTypeName(type));
				}
				else {
					objHash.addValue(type->getName());
				}
				return objHash.getHash();
			}

			shared::STypeUnit getTypeUnit(DataType::Type* type) {
				shared::STypeUnit typeUnitDesc;
				typeUnitDesc.__set_typeId(getId(type));
				/*typeUnitDesc.__set_pointerLvl(type->getPointerLvl());
				typeUnitDesc.__set_arraySize(type->getArraySize());*/
				return typeUnitDesc;
			}

			DataType::Type* getType(const shared::STypeUnit& typeUnitDesc) {
				return nullptr;//m_typeManager->getType(findTypeById(typeUnitDesc.typeId), typeUnitDesc.pointerLvl, typeUnitDesc.arraySize);
			}

			DataType::Type* findTypeById(datatype::Id id, bool returnDefType = true) {
				TypeManager::Iterator it(m_typeManager);
				while (it.hasNext()) {
					auto type = it.next();
					if (getId(type, false) == id) {
						return type;
					}
				}
				return returnDefType ? m_typeManager->getDefaultType() : nullptr;
			}

			datatype::SDataType buildDescToRemove(DataType::Type* type) {
				datatype::SDataType typeDesc;
				typeDesc.__set_id(getId(type));
				typeDesc.__set_size(0);
				return typeDesc;
			}

			datatype::SDataType buildTypeDesc(DataType::UserType* type) {
				datatype::SDataType typeDesc;
				typeDesc.__set_id(getId(type));
				typeDesc.__set_group((datatype::DataTypeGroup::type)type->getGroup());
				typeDesc.__set_size(type->getSize());
				typeDesc.__set_name(type->getName());
				typeDesc.__set_desc(type->getDesc());
				return typeDesc;
			}

			datatype::SDataTypeTypedef buildDesc(DataType::Typedef* Typedef) {
				datatype::SDataTypeTypedef typedefDesc;
				typedefDesc.__set_type(buildTypeDesc(Typedef));
				typedefDesc.refType.__set_typeId(Typedef->getRefType()->getId());
				/*typedefDesc.refType.__set_pointerLvl(Typedef->getRefType()->getPointerLvl());
				typedefDesc.refType.__set_arraySize(Typedef->getRefType()->getArraySize());*/
				return typedefDesc;
			}

			datatype::SDataTypeEnum buildDesc(DataType::Enum* enumeration) {
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

			datatype::SDataTypeStructure buildDesc(DataType::Class* Class) {
				datatype::SDataTypeStructure structDesc;
				structDesc.__set_type(buildTypeDesc(Class));

				int curOffset = 0;
				if (Class->hasVTable()) {
					datatype::SDataTypeStructureField structFieldDesc;
					structFieldDesc.__set_name("vtable");
					structFieldDesc.__set_offset(0);
					DataType::Void vtableType;
					structFieldDesc.type.__set_typeId(getId(&vtableType));
					structFieldDesc.type.__set_pointerLvl(1);
					structFieldDesc.type.__set_arraySize(0);
					structFieldDesc.__set_comment("{vtable}");
					structDesc.fields.push_back(structFieldDesc);
					curOffset = 0x8;
				}

				if (Class->getBaseClass() != nullptr) {
					DataType::Class* baseClass = Class->getBaseClass();
					datatype::SDataTypeStructureField structFieldDesc;
					structFieldDesc.__set_name(baseClass->getName());
					structFieldDesc.__set_offset(curOffset);
					structFieldDesc.type.__set_typeId(getId(baseClass));
					structFieldDesc.type.__set_pointerLvl(0);
					structFieldDesc.type.__set_arraySize(0);
					structFieldDesc.__set_comment("{base class}");
					structDesc.fields.push_back(structFieldDesc);
					//curOffset += baseClass->getSizeWithoutVTable();
				}

				/*Class->iterateFields([&](int offset, DataType::Class::Field* field_) {
					auto& field = *field_;
					datatype::SDataTypeStructureField structFieldDesc;
					structFieldDesc.__set_name(field.getName());
					structFieldDesc.__set_offset(curOffset + offset);
					structFieldDesc.type.__set_typeId(getId(field.getType()));
					structFieldDesc.type.__set_pointerLvl(field.getType()->getPointerLvl());
					structFieldDesc.type.__set_arraySize(field.getType()->getArraySize());
					structFieldDesc.__set_comment(field.getDesc());
					structDesc.fields.push_back(structFieldDesc);
					return true;
				});*/

				return structDesc;
			}

			void change(DataType::UserType* type, const datatype::SDataType& typeDesc) {
				type->setName(typeDesc.name);
				if (typeDesc.desc != "{pull}") {
					type->setDesc(typeDesc.desc);
				}
			}

			void change(DataType::Typedef* Typedef, const datatype::SDataTypeTypedef& typdefDesc) {
				auto ref_type = findTypeById(typdefDesc.refType.typeId);
				if (ref_type != nullptr) {
					/*Typedef->setRefType(getType(typdefDesc.refType));*/
				}
			}

			void change(DataType::Enum* enumeration, const datatype::SDataTypeEnum& enumDesc) {
				enumeration->setSize(enumDesc.type.size);
				enumeration->deleteAll();
				for (auto& field : enumDesc.fields) {
					enumeration->addField(field.name, field.value);
				}
			}

			void change(DataType::Class* Class, const datatype::SDataTypeStructure& structDesc) {
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
							if (type->getGroup() == DataType::Type::Class) {
								Class->setBaseClass(static_cast<DataType::Class*>(type));
								curField++;
							}
						}
					}
				}

				for (int i = curField; i < structDesc.fields.size(); i++) {
					auto& field = structDesc.fields[i];
					/*Class->addField(field.offset, field.name, getType(field.type), field.comment);*/
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

			DataType::Type* changeOrCreate(const datatype::SDataType& dataType) {
				auto type = findTypeById(dataType.id, false);
				if (type == nullptr) {
					switch (dataType.group)
					{
					case datatype::DataTypeGroup::Typedef:
						type = m_typeManager->createTypedef(DataType::GetUnit(m_typeManager->getDefaultType()), dataType.name, dataType.desc);
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
						change(static_cast<DataType::UserType*>(type), dataType);
					}
					else {
						type = nullptr;
					}
				}
				return type;
			}

			DataType::Typedef* changeOrCreate(const datatype::SDataTypeTypedef& Typedef) {
				auto type = static_cast<DataType::Typedef*>(changeOrCreate(Typedef.type));
				if (type == nullptr)
					return nullptr;
				change(type, Typedef);
				return type;
			}

			DataType::Enum* changeOrCreate(const datatype::SDataTypeEnum& enumeration) {
				auto type = static_cast<DataType::Enum*>(changeOrCreate(enumeration.type));
				if (type == nullptr)
					return nullptr;
				change(type, enumeration);
				return type;
			}

			DataType::Class* changeOrCreate(const datatype::SDataTypeStructure& structure) {
				auto type = static_cast<DataType::Class*>(changeOrCreate(structure.type));
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
			//MY TODO: исправить хеширование
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

			ObjectHash getHash(const datatype::SDataType& typeDesc) {
				ObjectHash hash;
				hash.addValue(typeDesc.name);
				hash.addValue(typeDesc.desc);
				return hash;
			}

			ObjectHash getHash(const datatype::SDataTypeTypedef& typedefDesc) {
				ObjectHash hash = getHash(typedefDesc.type);
				hash.addValue(typedefDesc.refType.typeId);
				hash.addValue(typedefDesc.refType.pointerLvl);
				hash.addValue(typedefDesc.refType.arraySize);
				return hash;
			}

			ObjectHash getHash(const datatype::SDataTypeStructure& structDesc) {
				ObjectHash hash = getHash(structDesc.type);
				for (auto& field : structDesc.fields) {
					ObjectHash fieldHash;
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

			ObjectHash getHash(const datatype::SDataTypeEnum& enumDesc) {
				ObjectHash hash = getHash(enumDesc.type);
				for (auto& field : enumDesc.fields) {
					ObjectHash fieldHash;
					fieldHash.addValue(field.name);
					fieldHash.addValue(field.value);
					hash.add(fieldHash);
				}
				return hash;
			}

			datatype::Hash getHash(DataType::Type* type) {
				switch (type->getGroup())
				{
				case DataType::Type::Typedef:
					return getHash(buildDesc(static_cast<DataType::Typedef*>(type))).getHash();
				case DataType::Type::Enum:
					return getHash(buildDesc(static_cast<DataType::Enum*>(type))).getHash();
				case DataType::Type::Class:
					return getHash(buildDesc(static_cast<DataType::Class*>(type))).getHash();
				}
				return 0;
			}

			HashMap generateHashMap() {
				HashMap hashmap;
				TypeManager::Iterator it(m_typeManager);
				while (it.hasNext()) {
					auto type = it.next();
					if (type->isUserDefined()) {
						auto usertype = static_cast<DataType::UserType*>(type);
						if (usertype->isGhidraUnit()) {
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
	};
};