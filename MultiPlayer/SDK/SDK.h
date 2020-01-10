#pragma once


//include SDK
#include "World/Ped/Ped.h"
#include "World/Vehicle/Vehicle.h"
#include "World/Ped/Weapon/Weapon.h"
#include "World/Bone.h"
#include "World/Ped/Task/TaskInvoker.h"
#include "UI/Text.h"
#include "Pool.h"
#include "Builder.h"
#include "Native.h"


#include "Core/ScriptLang/ClassBuilder.h"



/*
	ENUMS
	Regex to replace all:
	Source:			(\w+)\s+=\s(-?(0x)?\w+)
	Destinition:	["$1", $2]
*/



namespace SDK
{
	using namespace Class;

	class EXPORT
	{
	public:
		inline static Builder* Entity = nullptr;
		inline static Builder* Vehicle = nullptr;
		inline static Builder* Ped = nullptr;

		inline static Builder* PedPoolIterator = nullptr;
		inline static Builder* VehiclePoolIterator = nullptr;
		inline static Builder* ObjectPoolIterator = nullptr;

		inline static Builder* Vector2D = nullptr;
		inline static Builder* Vector3D = nullptr;
		inline static Builder* Model = nullptr;
		inline static Builder* PedModel = nullptr;
		inline static Builder* VehicleModel = nullptr;
		inline static Builder* Weapon = nullptr;
		inline static Builder* WeaponCollection = nullptr;
		inline static Builder* Anim = nullptr;
		inline static Builder* AnimDict = nullptr;
		inline static Builder* AnimConfig = nullptr;
		inline static Builder* TaskInvoker = nullptr;
		inline static Builder* EntityBone = nullptr;
		inline static Builder* PedBone = nullptr;
		inline static Builder* EntityBoneCollection = nullptr;
		inline static Builder* PedBoneCollection = nullptr;
		inline static Builder* UI_Text = nullptr;
		inline static Builder* Screen = nullptr;
		inline static Builder* Native = nullptr;
		inline static Builder* NativePointer = nullptr;
	private:
		inline static json* enumListData = nullptr;

		static void loadEnumListData() {
			JSON_Res res("SDK_ENUMS", GameAppInfo::GetInstancePtr()->getDLL());
			res.load();
			if (!res.isLoaded()) {
				//throw ex
				return;
			}

			enumListData = new json(res.getData());
		}

		static json& getEnum(Builder* Class, std::string enumName) {
			return (*enumListData)[Class->getName()][enumName];
		}

		static void unloadEnumListData() {
			delete enumListData;
		}
	public:

		static void buildAll()
		{
			//enum
			loadEnumListData();

			//Utilities
			Vector3D_build();
			Vector2D_build();

			//models
			Model_build();
			PedModel_build();
			VehicleModel_build();

			//Entities
			Entity_build();
			Ped_build();
			Vehicle_build();

			//Pools
			PedPoolIterator_build();
			VehiclePoolIterator_build();
			//ObjectPoolIterator_build();

			//Anim
			Anim_build();
			AnimDict_build();
			AnimConfig_build();

			//Task invoker
			TaskInvoker_build();

			//Collections
			Weapon_build();
			WeaponCollection_build();
			EntityBone_build();
			EntityBoneCollection_build();
			PedBone_build();
			PedBoneCollection_build();

			//UI
			UI_Text_build();
			Screen_build();

			//Native
			Native_build();
			NativePointer_build();

			//enum
			unloadEnumListData();
		}
		
		static void Vector3D_build()
		{
			Vector3D = new Builder("Vector3D");
			Vector3D
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::Vector3D)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::Vector3D)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(Vector3D::constructor)
					->setArgNames({ "x", "y", "z" })
				)
				->addMember(
				(new StaticMethod("Add"))
					SET_METHOD_LINK(Vector3D::Add)
					->setArgNames({ "vector1", "vector2" })
				)
				->addMember(
				(new StaticMethod("Sub"))
					SET_METHOD_LINK(Vector3D::Sub)
					->setArgNames({ "vector1", "vector2" })
				)
				->addMember(
				(new StaticMethod("Mul"))
					SET_METHOD_LINK(Vector3D::Mul)
					->setArgNames({ "vector1", "scalar" })
				)
				->addMember(
				(new Method("add"))
					SET_METHOD_LINK(&Vector3D::operator+=)
					->setArgNames({ "vector" })
				)
				->addMember(
				(new Method("sub"))
					SET_METHOD_LINK(&Vector3D::operator-=)
					->setArgNames({ "vector" })
				)
				->addMember(
				(new Method("mul"))
					SET_METHOD_LINK(&Vector3D::operator*=)
					->setArgNames({ "scalar" })
				)
				->addMember(
				(new Accessor("x"))
					SET_ACCESSOR_LINK(GET, &Vector3D::getX)
					SET_ACCESSOR_LINK(SET, &Vector3D::setX)
				)
				->addMember(
				(new Accessor("y"))
					SET_ACCESSOR_LINK(GET, &Vector3D::getY)
					SET_ACCESSOR_LINK(SET, &Vector3D::setY)
				)
				->addMember(
				(new Accessor("z"))
					SET_ACCESSOR_LINK(GET, &Vector3D::getZ)
					SET_ACCESSOR_LINK(SET, &Vector3D::setZ)
				);

			Environment::addClass<SDK::Vector3D>(Vector3D);
		}

		static void Vector2D_build()
		{
			Vector2D = new Builder("Vector2D");
			Vector2D
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::Vector2D)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::Vector2D)
				)
				->setParent(
					Vector3D
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(Vector2D::constructor)
					->setArgNames({ "x", "y" })
				);
			Environment::addClass<SDK::Vector2D>(Vector2D);
		}

		static void Model_build()
		{
			Model = new Builder("Model");
			Model
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::Model)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::Model)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(SDK::Model::constructor)
					->setArgNames({ "modelHash" })
				)
				->addMember(
				(new Accessor("isValid"))
					SET_ACCESSOR_LINK(GET, &Model::isValid)
				)
				->addMember(
				(new Accessor("isInCdImage"))
					SET_ACCESSOR_LINK(GET, &Model::isInCdImage)
				)
				->addMember(
				(new Accessor("isLoaded"))
					SET_ACCESSOR_LINK(GET, &Model::isLoaded)
				)
				->addMember(
				(new Accessor("isCollisionLoaded"))
					SET_ACCESSOR_LINK(GET, &Model::isCollisionLoaded)
				)
				->addMember(
				(new Method("request"))
					SET_METHOD_LINK(&Model::request)
				)
				->addMember(
				(new Method("load"))
					SET_METHOD_LINK(&Model::load)
					->setArgNames({ "timeout" })
					->setDefArgValues(std::make_tuple(2000))
				)
				->addMember(
				(new Method("requestCollision"))
					SET_METHOD_LINK(&Model::requestCollision)
				)
				->addMember(
				(new Method("loadCollision"))
					SET_METHOD_LINK(&Model::loadCollision)
					->setArgNames({ "timeout" })
					->setDefArgValues(std::make_tuple(2000))
				)
				->addMember(
				(new Method("markAsNoLongerNeeded"))
					SET_METHOD_LINK(&Model::markAsNoLongerNeeded)
				);
			Environment::addClass<SDK::Model>(Model);
		}

		static void PedModel_build()
		{
			PedModel = new Builder("PedModel");
			PedModel
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::PedModel)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::PedModel)
				)
				->setParent(
					Model
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(SDK::PedModel::constructor)
					->setArgNames({ "modelHash" })
				)
				->addMember(
				(new Method("request"))
					SET_METHOD_LINK(&PedModel::request)
				);
			Environment::addClass<SDK::PedModel>(PedModel);
		}

		static void VehicleModel_build()
		{
			VehicleModel = new Builder("VehicleModel");
			VehicleModel
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::VehicleModel)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::VehicleModel)
				)
				->setParent(
					Model
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(SDK::VehicleModel::constructor)
					->setArgNames({ "modelHash" })
				)
				->addMember(
				(new Accessor("isBicycle"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isBicycle)
				)
				->addMember(
				(new Accessor("isBike"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isBike)
				)
				->addMember(
				(new Accessor("isBoat"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isBoat)
				)
				->addMember(
				(new Accessor("isCar"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isCar)
				)
				->addMember(
				(new Accessor("isAmphibiousCar"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isAmphibiousCar)
				)
				->addMember(
				(new Accessor("isBlimp"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isBlimp)
				)
				->addMember(
				(new Accessor("isCargobob"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isCargobob)
				)
				->addMember(
				(new Accessor("isHelicopter"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isHelicopter)
				)
				->addMember(
				(new Accessor("isJetSki"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isJetSki)
				)
				->addMember(
				(new Accessor("isPlane"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isPlane)
				)
				->addMember(
				(new Accessor("isQuadBike"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isQuadBike)
				)
				->addMember(
				(new Accessor("isAmphibiousQuadBike"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isAmphibiousQuadBike)
				)
				->addMember(
				(new Accessor("isTrain"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isTrain)
				)
				->addMember(
				(new Accessor("isTrailer"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::isTrailer)
				)
				->addMember(
				(new Accessor("name"))
					SET_ACCESSOR_LINK(GET, &VehicleModel::getName)
				);
			Environment::addClass<SDK::VehicleModel>(VehicleModel);
		}

		static void Entity_build()
		{
			Entity = new Builder("Entity");
			Entity
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::Entity)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::Entity)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(SDK::Entity::constructor)
					->setArgNames({ "entityId" })
				)
				->addMember(
					SET_ENUM(Entity, SDK::Entity::Type, "Type")
				)
				->addMember(
				(new Accessor("id"))
					SET_ACCESSOR_LINK(GET, &Entity::getId)
				)
				->addMember(
				(new Accessor("type"))
					SET_ACCESSOR_LINK(GET, static_cast<Entity::Type(Entity::*)()>(&Entity::getType))
				)
				->addMember(
				(new Accessor("address"))
					SET_ACCESSOR_LINK(GET, &Entity::getAddr)
				)
				->addMember(
				(new Accessor("health"))
					SET_ACCESSOR_LINK(GET, &Entity::getHealth)
				)
				->addMember(
				(new Accessor("maxHealth"))
					SET_ACCESSOR_LINK(GET, &Entity::getMaxHealth)
				)
				->addMember(
				(new Accessor("isDead"))
					SET_ACCESSOR_LINK(GET, &Entity::isDead)
				)
				->addMember(
				(new Accessor("isAlive"))
					SET_ACCESSOR_LINK(GET, &Entity::isAlive)
				)
				->addMember(
				(new Accessor("isDead"))
					SET_ACCESSOR_LINK(GET, &Entity::isDead)
				)
				->addMember(
				(new Accessor("pos"))
					SET_ACCESSOR_LINK(GET, &Entity::getPos)
					SET_ACCESSOR_LINK(SET, &Entity::setPos)
				)
				->addMember(
				(new Accessor("rot"))
					SET_ACCESSOR_LINK(GET, &Entity::getRot)
					SET_ACCESSOR_LINK(SET, &Entity::setRot)
				)
				->addMember(
				(new Accessor("posNoOffset"))
					SET_ACCESSOR_LINK(SET, &Entity::setPosNoOffset)
				)
				->addMember(
				(new Accessor("heading"))
					SET_ACCESSOR_LINK(GET, &Entity::getHeading)
					SET_ACCESSOR_LINK(SET, &Entity::setHeading)
				)
				->addMember(
				(new Accessor("isPosFrozen"))
					SET_ACCESSOR_LINK(SET, &Entity::setPositionFrozen)
				)
				->addMember(
				(new Accessor("velocity"))
					SET_ACCESSOR_LINK(GET, &Entity::getVelocity)
					SET_ACCESSOR_LINK(SET, &Entity::setVelocity)
				)
				->addMember(
				(new Accessor("rotVelocity"))
					SET_ACCESSOR_LINK(GET, &Entity::getRotVelocity)
				)
				->addMember(
				(new Accessor("speed"))
					SET_ACCESSOR_LINK(GET, &Entity::getSpeed)
				)
				->addMember(
				(new Accessor("maxSpeed"))
					//SET_ACCESSOR_LINK(GET, &Entity::getM)
					SET_ACCESSOR_LINK(SET, &Entity::setMaxSpeed)
				)
				->addMember(
				(new Accessor("hasMaxGravity"))
					//SET_ACCESSOR_LINK(GET, &Entity::getM)
					SET_ACCESSOR_LINK(SET, &Entity::setHasMaxGravity)
				)
				->addMember(
				(new Accessor("heightAboveGround"))
					SET_ACCESSOR_LINK(GET, &Entity::getHeightAboveGround)
				)
				->addMember(
				(new Accessor("submersionLevel"))
					SET_ACCESSOR_LINK(GET, &Entity::getSubmersionLevel)
				)
				->addMember(
				(new Accessor("lodDistance"))
					SET_ACCESSOR_LINK(GET, &Entity::getLodDistance)
					SET_ACCESSOR_LINK(SET, &Entity::setLodDistance)
				)
				->addMember(
				(new Accessor("visible"))
					SET_ACCESSOR_LINK(GET, &Entity::isVisible)
					SET_ACCESSOR_LINK(SET, &Entity::setVisible)
				)
				->addMember(
				(new Accessor("isOccluded"))
					SET_ACCESSOR_LINK(GET, &Entity::isOccluded)
				)
				->addMember(
				(new Accessor("isOnScreen"))
					SET_ACCESSOR_LINK(GET, &Entity::isOnScreen)
				)
				->addMember(
				(new Accessor("isRendered"))
					SET_ACCESSOR_LINK(GET, &Entity::isRendered)
				)
				->addMember(
				(new Accessor("isUpright"))
					SET_ACCESSOR_LINK(GET, &Entity::isUpright)
				)
				->addMember(
				(new Accessor("isUpsideDown"))
					SET_ACCESSOR_LINK(GET, &Entity::isUpsideDown)
				)
				->addMember(
				(new Accessor("isInAir"))
					SET_ACCESSOR_LINK(GET, &Entity::isInAir)
				)
				->addMember(
				(new Accessor("isInWater"))
					SET_ACCESSOR_LINK(GET, &Entity::isInWater)
				)
				->addMember(
				(new Accessor("isPersistent"))
					SET_ACCESSOR_LINK(GET, &Entity::isPersistent)
					SET_ACCESSOR_LINK(SET, &Entity::setPersistent)
				)
				->addMember(
				(new Accessor("isOnFire"))
					SET_ACCESSOR_LINK(GET, &Entity::isOnFire)
				)
				->addMember(
				(new Accessor("isInvincible"))
					SET_ACCESSOR_LINK(GET, &Entity::isInvincible)
				)
				->addMember(
				(new Accessor("isOnlyDamagedByPlayer"))
					SET_ACCESSOR_LINK(GET, &Entity::isOnlyDamagedByPlayer)
					SET_ACCESSOR_LINK(SET, &Entity::setOnlyDamagedByPlayer)
				)
				->addMember(
				(new Accessor("opacity"))
					SET_ACCESSOR_LINK(GET, &Entity::getOpacity)
					SET_ACCESSOR_LINK(SET, &Entity::setOpacity)
				)
				->addMember(
				(new Method("resetOpacity"))
					SET_METHOD_LINK(&Entity::resetOpacity)
				)
				->addMember(
				(new Accessor("hasCollided"))
					SET_ACCESSOR_LINK(GET, &Entity::hasCollided)
				)
				->addMember(
				(new Accessor("isCollisionEnabled"))
					SET_ACCESSOR_LINK(GET, &Entity::isCollisionEnabled)
					SET_ACCESSOR_LINK(SET, &Entity::setCollisionEnabled)
				)
				->addMember(
				(new Accessor("recordingCollisions"))
					SET_ACCESSOR_LINK(SET, &Entity::setRecordingCollisions)
				)
				->addMember(
				(new Method("setNoCollision"))
					SET_METHOD_LINK(&Entity::setNoCollision)
					->setArgNames({ "entity", "toggle" })
				)
				->addMember(
				(new Method("hasBeenDamagedBy"))
					SET_METHOD_LINK(&Entity::hasBeenDamagedBy)
					->setArgNames({ "entity" })
				)
				->addMember(
				(new Accessor("hasBeenDamagedByAnyWeapon"))
					SET_ACCESSOR_LINK(GET, &Entity::hasBeenDamagedByAnyWeapon)
				)
				->addMember(
				(new Accessor("hasBeenDamagedByAnyMeleeWeapon"))
					SET_ACCESSOR_LINK(GET, &Entity::hasBeenDamagedByAnyMeleeWeapon)
				)
				->addMember(
				(new Method("clearLastWeaponDamage"))
					SET_METHOD_LINK(&Entity::ClearLastWeaponDamage)
				)
				->addMember(
				(new Accessor("isAttached"))
					SET_ACCESSOR_LINK(GET, &Entity::isAttached)
				)
				->addMember(
				(new Accessor("exists"))
					SET_ACCESSOR_LINK(GET, &Entity::exists)
				)
				->addMember(
				(new Method("isInArea"))
					SET_METHOD_LINK(&Entity::isInArea)
					->setArgNames({ "minBounds", "maxBounds" })
				)
				->addMember(
				(new Method("isInAngledArea"))
					SET_METHOD_LINK(&Entity::isInAngledArea)
					->setArgNames({ "origin", "edge", "angle" })
				)
				->addMember(
				(new Method("isNearEntity"))
					SET_METHOD_LINK(&Entity::isNearEntity)
					->setArgNames({ "entity", "bounds" })
				)
				->addMember(
				(new Method("isTouchingToModel"))
					//SET_METHOD_LINK(static_cast<bool(Entity::*)(SDK::Model)>(&Entity::isTouching))
				)
				->addMember(
				(new Method("isTouchingToEntity"))
					SET_METHOD_LINK(static_cast<bool(Entity::*)(SDK::Entity*)>(&Entity::isTouching))
					->setArgNames({ "entity" })
				)
				->addMember(
				(new Method("getOffsetPosition"))
					SET_METHOD_LINK(&Entity::getOffsetPosition)
					->setArgNames({ "offset" })
				)
				->addMember(
				(new Method("getPositionOffset"))
					SET_METHOD_LINK(&Entity::getPositionOffset)
					->setArgNames({ "worldCoords" })
				)
				->addMember(
				(new Method("attachTo"))
					SET_METHOD_LINK(&Entity::attachTo)
					->setArgNames({ "entity", "position", "rotation" })
				)
				->addMember(
				(new Method("detach"))
					SET_METHOD_LINK(&Entity::detach)
				)
				->addMember(
				(new Method("isAttachedTo"))
					SET_METHOD_LINK(&Entity::isAttachedTo)
					->setArgNames({ "entity" })
				)
				->addMember(
				(new Method("removeAllParticleEffects"))
					SET_METHOD_LINK(&Entity::removeAllParticleEffects)
				)
				->addMember(
				(new Method("markAsNoLongerNeeded"))
					SET_METHOD_LINK(&Entity::markAsNoLongerNeeded)
				)
				->addMember(
				(new StaticMethod("GetIdByAddress"))
					SET_METHOD_LINK(Entity::GetIdByAddress)
					->setArgNames({ "address" })
				);
			Environment::addClass<SDK::Entity>(Entity);
		}

		static void Ped_build()
		{
			using type = decltype(static_cast<SDK::Ped * (*)(SDK::PedModel, SDK::Vector3D, float, bool)>(CREATE::PED));

			Ped = new Builder("Ped");
			Ped
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::Ped)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::Ped)
				)
				->setParent(
					Entity
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(static_cast<SDK::Ped* (*)(SDK::PedModel, SDK::Vector3D, float, bool)>(CREATE::PED))
					->setArgNames({ "model", "position", "heading", "containers" })
					->setDefArgValues(std::make_tuple(Constructor::anyValue, Constructor::anyValue, 0.f, true))
				)
				->addMember(
				(new StaticMethod("New2"))
					SET_METHOD_LINK(static_cast<SDK::Ped* (*)(SDK::Ped::Type, SDK::PedModel, SDK::Vector3D, float, bool)>(CREATE::PED))
					->setArgNames({ "type", "model", "position", "heading", "containers" })
					->setDefArgValues(std::make_tuple(Constructor::anyValue, Constructor::anyValue, Constructor::anyValue, 0.f, true))
				)
				->addMember(
				(new StaticMethod("New3"))
					SET_METHOD_LINK(static_cast<SDK::Ped * (*)(SDK::Ped::Type, SE::Hash, SDK::Vector3D, float, bool)>(CREATE::PED))
					->setArgNames({ "type", "modelHash", "position", "heading", "containers" })
					->setDefArgValues(std::make_tuple(Constructor::anyValue, Constructor::anyValue, Constructor::anyValue, 0.f, true))
				)
				->addMember(
				(new StaticMethod("NewTest"))
					SET_METHOD_LINK(CREATE::PED_Test)
					->setArgNames({ "position", "heading" })
					->setDefArgValues(std::make_tuple(Constructor::anyValue, 0.f))
				)
				->addMember(
				(new StaticMethod("LocalPlayer"))
					SET_METHOD_LINK(CREATE::PED_LocalPlayer)
				)
				->addMember(
					SET_ENUM(Ped, SDK::Ped::Gender, "Gender")
				)
				->addMember(
					SET_ENUM(Ped, SDK::Ped::DrivingStyle, "DrivingStyle")
				)
				->addMember(
					SET_ENUM(Ped, SDK::Ped::VehicleDrivingFlags, "VehicleDrivingFlags")
				)
				->addMember(
					SET_ENUM(Ped, SDK::Ped::HelmetType, "HelmetType")
				)
				->addMember(
					SET_ENUM(Ped, SDK::Ped::ParachuteLandingType, "ParachuteLandingType")
				)
				->addMember(
					SET_ENUM(Ped, SDK::Ped::ParachuteState, "ParachuteState")
				)
				->addMember(
					SET_ENUM(Ped, SDK::Ped::RagdollType, "RagdollType")
				)
				->addMember(
					SET_ENUM(Ped, SDK::Ped::SpeechModifier, "SpeechModifier")
				)
				->addMember(
					SET_ENUM(Ped, SDK::Ped::Type, "Type")
				)
				->addMember(
					SET_ENUM(Ped, SDK::HASH::Ped, "Hash")
				)
				->addMember(
				(new Accessor("id"))
					SET_ACCESSOR_LINK(GET, &Ped::getId)
				)
				->addMember(
				(new Accessor("money"))
					SET_ACCESSOR_LINK(GET, &Ped::getMoney)
					SET_ACCESSOR_LINK(SET, &Ped::setMoney)
				)
				->addMember(
				(new Accessor("health"))
					SET_ACCESSOR_LINK(GET, &Ped::getHealth)
				)
				->addMember(
				(new Accessor("armour"))
					SET_ACCESSOR_LINK(GET, &Ped::getArmour)
					SET_ACCESSOR_LINK(SET, &Ped::setArmour)
				)
				->addMember(
				(new Accessor("gender"))
					SET_ACCESSOR_LINK(GET, &Ped::getGender)
				)
				->addMember(
				(new Accessor("bones"))
					SET_ACCESSOR_LINK(GET, &Ped::getBones)
					SET_ACCESSOR_LINK(SET, &Ped::setBoneCollection)
				)
				->addMember(
				(new Accessor("weapons"))
					SET_ACCESSOR_LINK(GET, &Ped::getWeapons)
					SET_ACCESSOR_LINK(SET, &Ped::setWeaponCollection)
				)
				->addMember(
				(new Accessor("taskInvoker"))
					SET_ACCESSOR_LINK(GET, &Ped::getTaskInvoker)
					SET_ACCESSOR_LINK(SET, &Ped::setTaskInvoker)
				)
				->addMember(
				(new Method("playAnim"))
					SET_METHOD_LINK(&Ped::playAnim)
					->setArgNames({ "anim" })
				);

			Environment::addClass<SDK::Ped>(Ped);
		}

		static void Vehicle_build()
		{
			Vehicle = new Builder("Vehicle");
			Vehicle
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::Vehicle)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::Vehicle)
				)
				->setParent(
					Entity
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(static_cast<SDK::Vehicle*(*)(SDK::VehicleModel, SDK::Vector3D, float)>(CREATE::VEHICLE))
					->setArgNames({ "model", "position", "heading" })
					->setDefArgValues(std::make_tuple(Constructor::anyValue, Constructor::anyValue, 0.f))
				)
				->addMember(
				(new StaticMethod("New2"))
					SET_METHOD_LINK(static_cast<SDK::Vehicle * (*)(SE::Hash, SDK::Vector3D, float)>(CREATE::VEHICLE))
					->setArgNames({ "modelHash", "position", "heading" })
					->setDefArgValues(std::make_tuple(Constructor::anyValue, Constructor::anyValue, 0.f))
				)
				->addMember(
				(new StaticMethod("NewTest"))
					SET_METHOD_LINK(CREATE::VEHICLE_Test)
					->setArgNames({ "position", "heading" })
					->setDefArgValues(std::make_tuple(Constructor::anyValue, 0.f))
				)
				->addMember(
					SET_ENUM(Vehicle, SDK::Vehicle::LicensePlateStyle, "LicensePlateStyle")
				)
				->addMember(
					SET_ENUM(Vehicle, SDK::Vehicle::LicensePlateType, "LicensePlateType")
				)
				->addMember(
					SET_ENUM(Vehicle, SDK::Vehicle::Class, "Class")
				)
				->addMember(
					SET_ENUM(Vehicle, SDK::Vehicle::Color, "Color")
				)
				->addMember(
					SET_ENUM(Vehicle, SDK::Vehicle::LandingGearState, "LandingGearState")
				)
				->addMember(
					SET_ENUM(Vehicle, SDK::Vehicle::LockStatus, "LockStatus")
				)
				->addMember(
					SET_ENUM(Vehicle, SDK::Vehicle::NeonLight, "NeonLight")
				)
				->addMember(
					SET_ENUM(Vehicle, SDK::Vehicle::RoofState, "RoofState")
				)
				->addMember(
					SET_ENUM(Vehicle, SDK::Vehicle::Seat, "Seat")
				)
				->addMember(
					SET_ENUM(Vehicle, SDK::Vehicle::WindowTint, "WindowTint")
				)
				->addMember(
					SET_ENUM(Vehicle, SDK::Vehicle::RadioStation, "RadioStation")
				)
				->addMember(
					SET_ENUM(Vehicle, SDK::HASH::Vehicle, "Hash")
				)
				->addMember(
				(new Accessor("id"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getId)
				)
				->addMember(
				(new Accessor("name"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getName)
				)
				->addMember(
				(new Accessor("model"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getModel)
				)
				->addMember(
				(new Accessor("className"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getClassName)
				)
				->addMember(
				(new Accessor("class"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getClass)
				)
				->addMember(
				(new Accessor("bodyHealth"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getBodyHealth)
					SET_ACCESSOR_LINK(SET, &Vehicle::setBodyHealth)
				)
				->addMember(
				(new Accessor("engineHealth"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getEngineHealth)
					SET_ACCESSOR_LINK(SET, &Vehicle::setEngineHealth)
				)
				->addMember(
				(new Accessor("petrolTankHealth"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getPetrolTankHealth)
					SET_ACCESSOR_LINK(SET, &Vehicle::setPetrolTankHealth)
				)
				->addMember(
				(new Accessor("engineRunning"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isEngineRunning)
					SET_ACCESSOR_LINK(SET, &Vehicle::setEngineRunning)
				)
				->addMember(
				(new Accessor("radioEnabled"))
					SET_ACCESSOR_LINK(SET, &Vehicle::setRadioEnabled)
				)
				->addMember(
				(new Accessor("radioStation"))
					SET_ACCESSOR_LINK(SET, &Vehicle::setRadioStation)
				)
				->addMember(
				(new Accessor("forwardSpeed"))
					SET_ACCESSOR_LINK(SET, &Vehicle::setForwardSpeed)
				)
				->addMember(
				(new Accessor("sirenActive"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isSirenActive)
					SET_ACCESSOR_LINK(SET, &Vehicle::setSirenActive)
				)
				->addMember(
				(new Accessor("sirenSilent"))
					SET_ACCESSOR_LINK(SET, &Vehicle::setSirenSilent)
				)
				->addMember(
				(new Accessor("lightsOn"))
					SET_ACCESSOR_LINK(GET, &Vehicle::areLightsOn)
					SET_ACCESSOR_LINK(SET, &Vehicle::setLightsOn)
				)
				->addMember(
				(new Accessor("highBeamsOn"))
					SET_ACCESSOR_LINK(GET, &Vehicle::areHighBeamsOn)
					SET_ACCESSOR_LINK(SET, &Vehicle::setHighBeamsOn)
				)
				->addMember(
				(new Accessor("lightsOnInInterior"))
					SET_ACCESSOR_LINK(GET, &Vehicle::areLightsOnInInterior)
					SET_ACCESSOR_LINK(SET, &Vehicle::setLightsOnInInterior)
				)
				->addMember(
				(new Accessor("searchLightOn"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isSearchLightOn)
					SET_ACCESSOR_LINK(SET, &Vehicle::setSearchLightOn)
				)
				->addMember(
				(new Accessor("taxiLightOn"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isTaxiLightOn)
					SET_ACCESSOR_LINK(SET, &Vehicle::setTaxiLightOn)
				)
				->addMember(
				(new Accessor("lightsOnInInterior"))
					SET_ACCESSOR_LINK(GET, &Vehicle::areLightsOnInInterior)
					SET_ACCESSOR_LINK(SET, &Vehicle::setLightsOnInInterior)
				)
				->addMember(
				(new Method("setIndicatorLightOn"))
					SET_METHOD_LINK(&Vehicle::setIndicatorLightOn)
					->setArgNames({ "indicator", "state" })
				)
				->addMember(
				(new Accessor("leftIndicatorLightOn"))
					SET_ACCESSOR_LINK(SET, &Vehicle::setLeftIndicatorLightOn)
				)
				->addMember(
				(new Accessor("rightIndicatorLightOn"))
					SET_ACCESSOR_LINK(SET, &Vehicle::setRightIndicatorLightOn)
				)
				->addMember(
				(new Accessor("handbrakeForcedOn"))
					SET_ACCESSOR_LINK(SET, &Vehicle::setHandbrakeForcedOn)
				)
				->addMember(
				(new Accessor("brakeLightsOn"))
					SET_ACCESSOR_LINK(SET, &Vehicle::setBrakeLightsOn)
				)
				->addMember(
				(new Accessor("canBeVisiblyDamaged"))
					SET_ACCESSOR_LINK(SET, &Vehicle::setCanBeVisiblyDamaged)
				)
				->addMember(
				(new Accessor("axlesStrong"))
					SET_ACCESSOR_LINK(SET, &Vehicle::setAxlesStrong)
				)
					->addMember(
				(new Accessor("canEngineDegrade"))
					SET_ACCESSOR_LINK(SET, &Vehicle::setCanEngineDegrade)
				)
				->addMember(
				(new Accessor("isDamaged"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isDamaged)
				)
				->addMember(
				(new Accessor("isDriveable"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isDriveable)
					SET_ACCESSOR_LINK(SET, &Vehicle::setDriveable)
				)
				->addMember(
				(new Accessor("hasRoof"))
					SET_ACCESSOR_LINK(GET, &Vehicle::hasRoof)
				)
				->addMember(
				(new Accessor("isRearBumperBrokenOff"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isRearBumperBrokenOff)
				)
				->addMember(
				(new Accessor("maxBraking"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getMaxBraking)
				)
				->addMember(
				(new Accessor("maxTraction"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getMaxTraction)
				)
				->addMember(
				(new Accessor("isOnAllWheels"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isOnAllWheels)
				)
				->addMember(
				(new Accessor("isStopped"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isStopped)
				)
				->addMember(
				(new Accessor("isStoppedAtTrafficLights"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isStoppedAtTrafficLights)
				)
				->addMember(
				(new Accessor("isConvertible"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isConvertible)
				)
				->addMember(
				(new Accessor("passengerCapacity"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getPassengerCapacity)
				)
				->addMember(
				(new Accessor("passengerCount"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getPassengerCount)
				)
				->addMember(
				(new Method("getPedOnSeat"))
					SET_METHOD_LINK(&Vehicle::getPedOnSeat)
					->setArgNames({ "seat" })
				)
				->addMember(
				(new Method("isSeatFree"))
					SET_METHOD_LINK(&Vehicle::isSeatFree)
					->setArgNames({ "seat" })
				)
				->addMember(
				(new Accessor("landingGearState"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getLandingGearState)
					SET_ACCESSOR_LINK(SET, &Vehicle::setLandingGearState)
				)
				->addMember(
				(new Accessor("roofState"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getRoofState)
					SET_ACCESSOR_LINK(SET, &Vehicle::setRoofState)
				)
				->addMember(
				(new Accessor("lockStatus"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getLockStatus)
					SET_ACCESSOR_LINK(SET, &Vehicle::setLockStatus)
				)
				->addMember(
				(new Accessor("isStolen"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isStolen)
					SET_ACCESSOR_LINK(SET, &Vehicle::setStolen)
				)
				->addMember(
				(new Accessor("isInBurnout"))
					SET_ACCESSOR_LINK(GET, &Vehicle::isInBurnout)
					SET_ACCESSOR_LINK(SET, &Vehicle::setBurnoutForced)
				)
				->addMember(
				(new Accessor("dirtLevel"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getDirtLevel)
					SET_ACCESSOR_LINK(SET, &Vehicle::setDirtLevel)
				)
				->addMember(
				(new Accessor("canTiresBurst"))
					SET_ACCESSOR_LINK(GET, &Vehicle::getCanTiresBurst)
					SET_ACCESSOR_LINK(SET, &Vehicle::setCanTiresBurst)
				)
				->addMember(
				(new Accessor("canWheelsBreak"))
					SET_ACCESSOR_LINK(SET, &Vehicle::setCanWheelsBreak)
				)
				->addMember(
				(new Method("placeOnGround"))
					SET_METHOD_LINK(&Vehicle::placeOnGround)
				)
				->addMember(
				(new Method("repair"))
					SET_METHOD_LINK(&Vehicle::repair)
				)
				->addMember(
				(new Method("explode"))
					SET_METHOD_LINK(&Vehicle::explode)
				);
			Environment::addClass<SDK::Vehicle>(Vehicle);
		}

		static void PedPoolIterator_build()
		{
			PedPoolIterator = new Builder("PedPoolIterator");
			PedPoolIterator
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::Pool::Ped)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::Pool::Ped)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(Pool::Ped::constructor)
				)
				->addMember(
				(new Method("next"))
					SET_METHOD_LINK(&Pool::Ped::next)
				)
				->addMember(
				(new Method("hasNext"))
					SET_METHOD_LINK(&Pool::Ped::hasNext)
				);
			Environment::addClass<Pool::Ped>(PedPoolIterator);
		}

		static void VehiclePoolIterator_build()
		{
			VehiclePoolIterator = new Builder("VehiclePoolIterator");
			VehiclePoolIterator
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::Pool::Vehicle)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::Pool::Vehicle)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(Pool::Vehicle::constructor)
				)
				->addMember(
				(new Method("next"))
					SET_METHOD_LINK(&Pool::Vehicle::next)
				)
				->addMember(
				(new Method("hasNext"))
					SET_METHOD_LINK(&Pool::Vehicle::hasNext)
				);
			Environment::addClass<Pool::Vehicle>(VehiclePoolIterator);
		}

		/*
		static void ObjectPoolIterator_build()
		{
			ObjectPoolIterator = new Builder("ObjectPoolIterator");
			ObjectPoolIterator
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::Pool::Object)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::Pool::Object)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(Pool::Object::constructor)
				)
				->addMember(
				(new Method("next"))
					SET_METHOD_LINK(&Pool::Object::next)
				)
				->addMember(
				(new Method("hasNext"))
					SET_METHOD_LINK(&Pool::Object::hasNext)
				);
			Environment::addClass<Pool::Object>(ObjectPoolIterator);
		}*/

		static void Weapon_build()
		{
			Weapon = new Builder("Weapon");
			Weapon
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::Weapon)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::Weapon)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(Weapon::constructor)
					->setArgNames({ "hash", "owner" })
				)
				->addMember(
					SET_ENUM(Weapon, SDK::Weapon::Group, "Group")
				)
				->addMember(
					SET_ENUM(Weapon, SDK::HASH::Weapon, "Hash")
				)
				->addMember(
					SET_ENUM(Weapon, SDK::HASH::VehicleWeapon, "VehHash")
				)
				->addMember(
				(new Accessor("hash"))
					SET_ACCESSOR_LINK(GET, &Weapon::getHash)
				)
				->addMember(
				(new Accessor("isPresent"))
					SET_ACCESSOR_LINK(GET, &Weapon::isPresent)
				)
				->addMember(
				(new Accessor("isUnarmed"))
					SET_ACCESSOR_LINK(GET, &Weapon::isUnarmed)
				)
				->addMember(
				(new Accessor("isValid"))
					SET_ACCESSOR_LINK(GET, &Weapon::isValid)
				)
				->addMember(
				(new Accessor("model"))
					SET_ACCESSOR_LINK(GET, &Weapon::getModel)
				)
				->addMember(
				(new Accessor("group"))
					SET_ACCESSOR_LINK(GET, &Weapon::getGroup)
				)
				->addMember(
				(new Accessor("ammo"))
					SET_ACCESSOR_LINK(GET, &Weapon::getAmmo)
					SET_ACCESSOR_LINK(SET, &Weapon::setAmmo)
				)
				->addMember(
				(new Accessor("ammoInClip"))
					SET_ACCESSOR_LINK(GET, &Weapon::getAmmoInClip)
					SET_ACCESSOR_LINK(SET, &Weapon::setAmmoInClip)
				)
				->addMember(
				(new Accessor("maxAmmo"))
					SET_ACCESSOR_LINK(GET, &Weapon::getMaxAmmo)
				)
				->addMember(
				(new Accessor("maxAmmoInClip"))
					SET_ACCESSOR_LINK(GET, &Weapon::getMaxAmmoInClip)
				)
				->addMember(
				(new Accessor("defaultClipSize"))
					SET_ACCESSOR_LINK(GET, &Weapon::getDefaultClipSize)
				)
				->addMember(
				(new Accessor("canUseOnParachute"))
					SET_ACCESSOR_LINK(GET, &Weapon::canUseOnParachute)
				)
				->addMember(
				(new Accessor("infiniteAmmo"))
					SET_ACCESSOR_LINK(SET, &Weapon::setInfiniteAmmo)
				)
				->addMember(
				(new Accessor("infiniteAmmoClip"))
					SET_ACCESSOR_LINK(SET, &Weapon::setInfiniteAmmoClip)
				);
				
			Environment::addClass<SDK::Weapon>(Weapon);
		}

		static void WeaponCollection_build()
		{
			WeaponCollection = new Builder("WeaponCollection");
			WeaponCollection
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::WeaponCollection)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::WeaponCollection)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(WeaponCollection::constructor)
					->setArgNames({ "owner" })
				)

				//Item manager
				->addMember(
				(new Method("getItem"))
					SET_METHOD_LINK((&IPedCollection<HASH::Weapon, SDK::Weapon>::getItem))
					->setArgNames({ "id" })
				)
				->addMember(
				(new Method("createItem"))
					SET_METHOD_LINK(&WeaponCollection::createItem)
					->setArgNames({ "id" })
				)
				->addMember(
				(new Method("hasItem"))
					SET_METHOD_LINK(&WeaponCollection::hasItem)
					->setArgNames({ "id" })
				)

				->addMember(
				(new Accessor("current"))
					SET_ACCESSOR_LINK(GET, &WeaponCollection::getCurrent)
				)
				->addMember(
				(new Method("hasWeapon"))
					SET_METHOD_LINK(&WeaponCollection::hasWeapon)
					->setArgNames({ "weapon" })
				)
				->addMember(
				(new Method("give"))
					SET_METHOD_LINK(&WeaponCollection::give)
					->setArgNames({ "id", "ammo", "equipNow", "isAmmoLoaded" })
					->setDefArgValues(std::make_tuple(
						Method::anyValue, Method::anyValue, true, true
					))
				)
				->addMember(
				(new Method("select"))
					SET_METHOD_LINK(static_cast<void(WeaponCollection::*)(SDK::Weapon*)>(&WeaponCollection::select))
					->setArgNames({ "weapon" })
				)
				->addMember(
				(new Method("selectById"))
					SET_METHOD_LINK(static_cast<void(WeaponCollection::*)(HASH::Weapon)>(&WeaponCollection::select))
					->setArgNames({ "id" })
				)
				->addMember(
				(new Method("drop"))
					SET_METHOD_LINK(&WeaponCollection::drop)
				)
				->addMember(
				(new Method("remove"))
					SET_METHOD_LINK(&WeaponCollection::remove)
					->setArgNames({ "id" })
				)
				->addMember(
				(new Method("removeAll"))
					SET_METHOD_LINK(&WeaponCollection::removeAll)
				)
				->addMember(
				(new Accessor("owner"))
					SET_ACCESSOR_LINK(GET, (&IPedCollection<HASH::Weapon, SDK::Weapon>::getOwner))
				);
			Environment::addClass<SDK::WeaponCollection>(WeaponCollection);
		}

		static void Anim_build()
		{
			Anim = new Builder("Anim");
			Anim
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(ANIM::Anim)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(ANIM::Anim)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(ANIM::Anim::constructor)
					->setArgNames({ "dictionaryName", "animationName" })
				)
				->addMember(
					SET_ENUM(Anim, SDK::ANIM::Flags, "Flags")
				)
				->addMember(
				(new Accessor("config"))
					SET_ACCESSOR_LINK(SET, &ANIM::Anim::setConfig)
				)
				->addMember(
				(new Accessor("playbackRate"))
					SET_ACCESSOR_LINK(GET, &ANIM::Anim::getPlaybackRate)
					SET_ACCESSOR_LINK(SET, &ANIM::Anim::setPlaybackRate)
				)
				->addMember(
				(new Accessor("inSpeed"))
					SET_ACCESSOR_LINK(GET, &ANIM::Anim::getInSpeed)
					SET_ACCESSOR_LINK(SET, &ANIM::Anim::setInSpeed)
				)
				->addMember(
				(new Accessor("outSpeed"))
					SET_ACCESSOR_LINK(GET, &ANIM::Anim::getOutSpeed)
					SET_ACCESSOR_LINK(SET, &ANIM::Anim::setOutSpeed)
				)
				->addMember(
				(new Accessor("duration"))
					SET_ACCESSOR_LINK(GET, &ANIM::Anim::getDuration)
					SET_ACCESSOR_LINK(SET, &ANIM::Anim::setDuration)
				)
				->addMember(
				(new Accessor("flags"))
					SET_ACCESSOR_LINK(GET, &ANIM::Anim::getFlags)
					SET_ACCESSOR_LINK(SET, &ANIM::Anim::setFlags)
				)
				->addMember(
				(new Method("setConfig"))
					SET_METHOD_LINK(&ANIM::Anim::setConfig)
					->setArgNames({ "config" })
				)
				->addMember(
				(new Method("setPlaybackRate"))
					SET_METHOD_LINK(&ANIM::Anim::setPlaybackRate)
					->setArgNames({ "pbRate" })
				)
				->addMember(
				(new Method("setInSpeed"))
					SET_METHOD_LINK(&ANIM::Anim::setInSpeed)
					->setArgNames({ "inSpeed" })
				)
				->addMember(
				(new Method("setOutSpeed"))
					SET_METHOD_LINK(&ANIM::Anim::setOutSpeed)
					->setArgNames({ "outSpeed" })
				)
				->addMember(
				(new Method("setSpeed"))
					SET_METHOD_LINK(&ANIM::Anim::setSpeed)
					->setArgNames({ "speed" })
				)
				->addMember(
				(new Method("setDuration"))
					SET_METHOD_LINK(&ANIM::Anim::setDuration)
					->setArgNames({ "duration" })
				)
				->addMember(
				(new Method("setFlags"))
					SET_METHOD_LINK(&ANIM::Anim::setFlags)
					->setArgNames({ "flags" })
				)
				->addMember(
				(new Accessor("name"))
					SET_ACCESSOR_LINK(GET, &ANIM::Anim::getName)
				)
				->addMember(
				(new Accessor("dictionary"))
					SET_ACCESSOR_LINK(GET, &ANIM::Anim::getDict)
				);
			Environment::addClass<SDK::ANIM::Anim>(Anim);
		}

		static void AnimDict_build()
		{
			AnimDict = new Builder("AnimDict");
			AnimDict
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(ANIM::Dict)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(ANIM::Dict)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(ANIM::Dict::constructor)
					->setArgNames({ "path" })
				)
				->addMember(
				(new Accessor("path"))
					SET_ACCESSOR_LINK(GET, &ANIM::Dict::getPath)
				)
				->addMember(
				(new Accessor("isValid"))
					SET_ACCESSOR_LINK(GET, &ANIM::Dict::isValid)
				)
				->addMember(
				(new Accessor("isLoaded"))
					SET_ACCESSOR_LINK(GET, &ANIM::Dict::isLoaded)
				)
				->addMember(
				(new Method("next"))
					SET_METHOD_LINK(&ANIM::Dict::operator[])
					->setArgNames({ "path" })
				)
				->addMember(
				(new Method("get"))
					SET_METHOD_LINK(&ANIM::Dict::get)
					->setArgNames({ "name" })
				)
				->addMember(
				(new Method("request"))
					SET_METHOD_LINK(&ANIM::Dict::request)
				)
				->addMember(
				(new Method("load"))
					SET_METHOD_LINK(&ANIM::Dict::load)
					->setArgNames({ "timeout" })
					->setDefArgValues(std::make_tuple(2000))
				);
			Environment::addClass<SDK::ANIM::Dict>(AnimDict);
		}

		static void AnimConfig_build()
		{
			AnimConfig = new Builder("AnimConfig");
			AnimConfig
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(ANIM::Anim::Config)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(ANIM::Anim::Config)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(ANIM::Anim::Config::constructor)
					->setArgNames({ "inSpeed", "outSpeed", "duration", "flags", "playbackRate" })
				);
			Environment::addClass<SDK::ANIM::Anim::Config>(AnimConfig);
		}

		static void TaskInvoker_build()
		{
			TaskInvoker = new Builder("TaskInvoker");
			TaskInvoker
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::TaskInvoker)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::TaskInvoker)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(TaskInvoker::constructor)
					->setArgNames({ "owner" })
				)
				->addMember(
					SET_ENUM(TaskInvoker, SDK::FiringPattern, "FiringPattern")
				)
				->addMember(
					SET_ENUM(TaskInvoker, SDK::EnterVehicleFlags, "EnterVehicleFlags")
				)
				->addMember(
					SET_ENUM(TaskInvoker, SDK::LeaveVehicleFlags, "LeaveVehicleFlags")
				)
				->addMember(
				(new Method("achieveHeading"))
					SET_METHOD_LINK(&TaskInvoker::AchieveHeading)
					->setArgNames({ "heading", "timeout" })
				)
				->addMember(
				(new Method("aimAtEntity"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Entity*, int)>(&TaskInvoker::AimAt))
					->setArgNames({ "target", "duration" })
				)
				->addMember(
				(new Method("aimAtCoord"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Vector3D, int)>(&TaskInvoker::AimAt))
					->setArgNames({ "target", "duration" })
				)
				->addMember(
				(new Method("arrest"))
					SET_METHOD_LINK(&TaskInvoker::Arrest)
					->setArgNames({ "ped" })
				)
				->addMember(
				(new Method("chatTo"))
					SET_METHOD_LINK(&TaskInvoker::ChatTo)
					->setArgNames({ "ped" })
				)
				->addMember(
				(new Method("jump"))
					SET_METHOD_LINK(&TaskInvoker::Jump)
				)
				->addMember(
				(new Method("climb"))
					SET_METHOD_LINK(&TaskInvoker::Climb)
				)
				->addMember(
				(new Method("climbLadder"))
					SET_METHOD_LINK(&TaskInvoker::ClimbLadder)
				)
				->addMember(
				(new Method("cower"))
					SET_METHOD_LINK(&TaskInvoker::Cower)
					->setArgNames({ "duration" })
				)
				->addMember(
				(new Method("chaseWithGroundVehicle"))
					SET_METHOD_LINK(&TaskInvoker::ChaseWithGroundVehicle)
					->setArgNames({ "target" })
				)
				->addMember(
				(new Method("chaseWithHelicopter"))
					SET_METHOD_LINK(&TaskInvoker::ChaseWithHelicopter)
					->setArgNames({ "target", "offset" })
				)
				->addMember(
				(new Method("chaseWithPlane"))
					SET_METHOD_LINK(&TaskInvoker::ChaseWithPlane)
					->setArgNames({ "target", "offset" })
				)
				->addMember(
				(new Method("cruiseWithVehicle"))
					SET_METHOD_LINK(&TaskInvoker::CruiseWithVehicle)
					->setArgNames({ "vehicle", "speed", "style" })
					->setDefArgValues(std::make_tuple(Method::anyValue, Method::anyValue, Ped::Normal))
				)
				->addMember(
				(new Method("driveTo"))
					SET_METHOD_LINK(&TaskInvoker::DriveTo)
					->setArgNames({ "vehicle", "target", "radius", "speed", "style" })
					->setDefArgValues(std::make_tuple(Method::anyValue, Method::anyValue, Method::anyValue, Method::anyValue, Ped::Normal))
				)
				->addMember(
				(new Method("enterAnyVehicle"))
					SET_METHOD_LINK(&TaskInvoker::EnterAnyVehicle)
					->setArgNames({ "seat", "timeout", "speed", "flags" })
					->setDefArgValues(std::make_tuple(Vehicle::Seat::Any, -1, 1.0f, EnterVehicleFlags::None))
				)
				->addMember(
				(new Method("enterVehicle"))
					SET_METHOD_LINK(&TaskInvoker::EnterVehicle)
					->setArgNames({ "vehicle", "seat", "timeout", "speed", "flags" })
					->setDefArgValues(std::make_tuple(Method::anyValue, Vehicle::Seat::Any, -1, 1.0f, EnterVehicleFlags::None))
				)
				->addMember(
				(new Method("fightAgainst"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Ped*)>(&TaskInvoker::FightAgainst))
					->setArgNames({ "target" })
				)
				->addMember(
				(new Method("fightAgainstWithDuration"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Ped*, int)>(&TaskInvoker::FightAgainst))
					->setArgNames({ "target", "duration" })
				)
				->addMember(
				(new Method("fightAgainstHatedTargets"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(float)>(&TaskInvoker::FightAgainstHatedTargets))
					->setArgNames({ "radius" })
				)
				->addMember(
				(new Method("fightAgainstHatedTargetsWithDuration"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(float, int)>(&TaskInvoker::FightAgainstHatedTargets))
					->setArgNames({ "radius", "duration" })
				)
				->addMember(
				(new Method("fleeFromPed"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Ped*, int)>(&TaskInvoker::FleeFrom))
					->setArgNames({ "ped", "duration" })
				)
				->addMember(
				(new Method("fleeFromCoord"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Vector3D, int)>(&TaskInvoker::FleeFrom))
					->setArgNames({ "position", "duration" })
				)
				->addMember(
				(new Method("followToOffsetFromEntity"))
					SET_METHOD_LINK(&TaskInvoker::FollowToOffsetFromEntity)
					->setArgNames({ "target", "offset", "movementSpeed", "timeout", "distanceToFollow", "persistFollowing" })
					->setDefArgValues(std::make_tuple(Method::anyValue, Method::anyValue, Method::anyValue, Vehicle::Seat::Any, -1, 10.0f, true))
				)
				->addMember(
				(new Method("goToEntity"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Entity*, SDK::Vector3D, int)>(&TaskInvoker::GoTo))
					->setArgNames({ "entity", "position", "timeout" })
					->setDefArgValues(std::make_tuple(Method::anyValue, Method::anyValue, -1))
				)
				->addMember(
				(new Method("goToCoord"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Vector3D, int)>(&TaskInvoker::GoTo))
					->setArgNames({ "position", "timeout" })
					->setDefArgValues(std::make_tuple(Method::anyValue, -1))
				)
				->addMember(
				(new Method("goStraightTo"))
					SET_METHOD_LINK(&TaskInvoker::GoStraightTo)
					->setArgNames({ "position", "timeout", "targetHeading", "distanceToSlide" })
					->setDefArgValues(std::make_tuple(Method::anyValue, -1, 0, 0))
				)
				->addMember(
				(new Method("guardCurrentPosition"))
					SET_METHOD_LINK(&TaskInvoker::GuardCurrentPosition)
				)
				->addMember(
				(new Method("handsUp"))
					SET_METHOD_LINK(&TaskInvoker::HandsUp)
					->setArgNames({ "duration" })
					->setDefArgValues(std::make_tuple(Method::anyValue))
				)
				->addMember(
				(new Method("leaveVehicle"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(LeaveVehicleFlags)>(&TaskInvoker::LeaveVehicle))
					->setArgNames({ "flags" })
					->setDefArgValues(std::make_tuple(LeaveVehicleFlags::None))
				)
				->addMember(
				(new Method("leaveThisVehicle"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Vehicle*, LeaveVehicleFlags)>(&TaskInvoker::LeaveVehicle))
					->setArgNames({ "vehicle", "flags" })
				)
				->addMember(
				(new Method("lookAtEntity"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Entity*, int)>(&TaskInvoker::LookAt))
					->setArgNames({ "target", "duration" })
					->setDefArgValues(std::make_tuple(Method::anyValue, -1))
				)
				->addMember(
				(new Method("lookAtCoord"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Vector3D, float)>(&TaskInvoker::LookAt))
					->setArgNames({ "position", "duration" })
					->setDefArgValues(std::make_tuple(Method::anyValue, -1))
				)
				->addMember(
				(new Method("parachuteTo"))
					SET_METHOD_LINK(&TaskInvoker::ParachuteTo)
					->setArgNames({ "position" })
				)
				->addMember(
				(new Method("parkVehicle"))
					SET_METHOD_LINK(&TaskInvoker::ParkVehicle)
					->setArgNames({ "vehicle", "position", "heading", "radius", "keepEngineOn" })
					->setDefArgValues(std::make_tuple(Method::anyValue, Method::anyValue, Method::anyValue, 20.f, false))
				)
				->addMember(
				(new Method("rappelFromHelicopter"))
					SET_METHOD_LINK(&TaskInvoker::RappelFromHelicopter)
				)
				->addMember(
				(new Method("reactAndFlee"))
					SET_METHOD_LINK(&TaskInvoker::ReactAndFlee)
					->setArgNames({ "ped" })
				)
				->addMember(
				(new Method("reloadWeapon"))
					SET_METHOD_LINK(&TaskInvoker::ReloadWeapon)
				)
				->addMember(
				(new Method("shootAtPed"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Ped*, int, FiringPattern)>(&TaskInvoker::ShootAt))
					->setArgNames({ "target", "duration", "pattern" })
					->setDefArgValues(std::make_tuple(Method::anyValue, -1, FiringPattern::Default))
				)
				->addMember(
				(new Method("shootAtCoord"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Vector3D, int, FiringPattern)>(&TaskInvoker::ShootAt))
					->setArgNames({ "position", "duration", "pattern" })
					->setDefArgValues(std::make_tuple(Method::anyValue, -1, FiringPattern::Default))
				)
				->addMember(
				(new Method("skydive"))
					SET_METHOD_LINK(&TaskInvoker::Skydive)
				)
				->addMember(
				(new Method("slideTo"))
					SET_METHOD_LINK(&TaskInvoker::SlideTo)
					->setArgNames({ "position", "heading" })
				)
				->addMember(
				(new Method("standStill"))
					SET_METHOD_LINK(&TaskInvoker::StandStill)
					->setArgNames({ "duration" })
				)
				->addMember(
				(new Method("startScenario"))
					SET_METHOD_LINK(&TaskInvoker::StartScenario)
					->setArgNames({ "name", "position" })
				)
				->addMember(
				(new Method("swapWeapon"))
					SET_METHOD_LINK(&TaskInvoker::SwapWeapon)
				)
				->addMember(
				(new Method("turnToEntity"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Entity*, int)>(&TaskInvoker::TurnTo))
					->setArgNames({ "target", "duration" })
				)
				->addMember(
				(new Method("turnToCoord"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Vector3D, int)>(&TaskInvoker::TurnTo))
					->setArgNames({ "position", "duration" })
				)
				->addMember(
				(new Method("useParachute"))
					SET_METHOD_LINK(&TaskInvoker::UseParachute)
				)
				->addMember(
				(new Method("useMobilePhone"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)()>(&TaskInvoker::UseMobilePhone))
				)
				->addMember(
				(new Method("useMobilePhoneWithDuration"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(int)>(&TaskInvoker::UseMobilePhone))
					->setArgNames({ "duration" })
				)
				->addMember(
				(new Method("putAwayParachute"))
					SET_METHOD_LINK(&TaskInvoker::PutAwayParachute)
				)
				->addMember(
				(new Method("putAwayMobilePhone"))
					SET_METHOD_LINK(&TaskInvoker::PutAwayMobilePhone)
				)
				->addMember(
				(new Method("vehicleChase"))
					SET_METHOD_LINK(&TaskInvoker::VehicleChase)
					->setArgNames({ "target" })
				)
				->addMember(
				(new Method("vehicleShootAtPed"))
					SET_METHOD_LINK(&TaskInvoker::VehicleShootAtPed)
					->setArgNames({ "target" })
				)
				->addMember(
				(new Method("wait"))
					SET_METHOD_LINK(&TaskInvoker::Wait)
					->setArgNames({ "duration" })
				)
				->addMember(
				(new Method("wanderAround"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)()>(&TaskInvoker::WanderAround))
				)
				->addMember(
				(new Method("wanderAroundCoord"))
					SET_METHOD_LINK(static_cast<void(TaskInvoker::*)(SDK::Vector3D, float)>(&TaskInvoker::WanderAround))
					->setArgNames({ "position", "duration" })
				)
				->addMember(
				(new Method("warpIntoVehicle"))
					SET_METHOD_LINK(&TaskInvoker::WarpIntoVehicle)
					->setArgNames({ "vehicle", "seat" })
				)
				->addMember(
				(new Method("warpOutOfVehicle"))
					SET_METHOD_LINK(&TaskInvoker::WarpOutOfVehicle)
					->setArgNames({ "vehicle" })
				)
				->addMember(
				(new Method("clearAll"))
					SET_METHOD_LINK(&TaskInvoker::ClearAll)
				)
				->addMember(
				(new Method("clearAllImmediately"))
					SET_METHOD_LINK(&TaskInvoker::ClearAllImmediately)
				)
				->addMember(
				(new Method("clearLookAt"))
					SET_METHOD_LINK(&TaskInvoker::ClearLookAt)
				)
				->addMember(
				(new Method("clearSecondary"))
					SET_METHOD_LINK(&TaskInvoker::ClearSecondary)
				)
				->addMember(
				(new Method("clearAnimation"))
					SET_METHOD_LINK(&TaskInvoker::ClearAnimation)
					->setArgNames({ "animationSet", "animationName" })
				);
			Environment::addClass<SDK::TaskInvoker>(TaskInvoker);
		}

		static void EntityBone_build()
		{
			EntityBone = new Builder("EntityBone");
			EntityBone
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::EntityBone)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::EntityBone)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(SDK::EntityBone::constructor)
					->setArgNames({ "index", "owner" })
				)
				->addMember(
				(new Accessor("pos"))
					SET_ACCESSOR_LINK(GET, &EntityBone::getPos)
				)
				->addMember(
				(new Accessor("isValid"))
					SET_ACCESSOR_LINK(GET, &EntityBone::isValid)
				)
				->addMember(
				(new Accessor("index"))
					SET_ACCESSOR_LINK(GET, &EntityBone::getIndex)
				)
				->addMember(
				(new Accessor("owner"))
					SET_ACCESSOR_LINK(GET, &EntityBone::getOwner)
				)
				->addMember(
				(new StaticMethod("getIndexByName"))
					SET_METHOD_LINK(EntityBone::getIndexByName)
					->setArgNames({ "entity", "boneName" })
				);
			Environment::addClass<SDK::EntityBone>(EntityBone);
		}

		static void PedBone_build()
		{
			PedBone = new Builder("PedBone");
			PedBone
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::PedBone)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::PedBone)
				)
				->setParent(
					EntityBone
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(SDK::PedBone::constructor)
					->setArgNames({ "index", "owner" })
				)
				->addMember(
					SET_ENUM(PedBone, SDK::HASH::PedBone, "Hash")
				)
				->addMember(
				(new StaticMethod("getIndexByPedBone"))
					SET_METHOD_LINK(PedBone::getIndexByPedBone)
					->setArgNames({ "ped", "bone" })
				);
			Environment::addClass<SDK::PedBone>(PedBone);
		}

		static void EntityBoneCollection_build()
		{
			EntityBoneCollection = new Builder("EntityBoneCollection");
			EntityBoneCollection
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::EntityBoneCollection)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::EntityBoneCollection)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(SDK::EntityBoneCollection::constructor)
					->setArgNames({ "owner" })
				)

				//Item manager
				->addMember(
				(new Method("getItem"))
					SET_METHOD_LINK((&IEntityCollection<EntityBone::Type, SDK::EntityBone>::getItem))
					->setArgNames({ "id" })
				)
				->addMember(
				(new Method("createItem"))
					SET_METHOD_LINK(&EntityBoneCollection::createItem)
					->setArgNames({ "id" })
				)
				->addMember(
				(new Method("hasItem"))
					SET_METHOD_LINK(&EntityBoneCollection::hasItem)
					->setArgNames({ "id" })
				)

				->addMember(
				(new Accessor("owner"))
					SET_ACCESSOR_LINK(GET, (&IEntityCollection<EntityBone::Type, SDK::EntityBone>::getOwner))
				);
			Environment::addClass<SDK::EntityBoneCollection>(EntityBoneCollection);
		}

		static void PedBoneCollection_build()
		{
			PedBoneCollection = new Builder("PedBoneCollection");
			PedBoneCollection
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::PedBoneCollection)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::PedBoneCollection)
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(SDK::PedBoneCollection::constructor)
					->setArgNames({ "owner" })
				)

				//Item manager
				->addMember(
				(new Method("getItem"))
					SET_METHOD_LINK((&IPedCollection<HASH::PedBone, SDK::PedBone>::getItem))
					->setArgNames({ "id" })
				)
				->addMember(
				(new Method("createItem"))
					SET_METHOD_LINK(&PedBoneCollection::createItem)
					->setArgNames({ "id" })
				)
				->addMember(
				(new Method("hasItem"))
					SET_METHOD_LINK(&PedBoneCollection::hasItem)
					->setArgNames({ "id" })
				)

				->addMember(
				(new Accessor("lastDamaged"))
					SET_ACCESSOR_LINK(GET, &PedBoneCollection::getLastDamaged)
				)
				->addMember(
				(new Method("clearLastDamaged"))
					SET_METHOD_LINK(&PedBoneCollection::clearLastDamaged)
				)
				->addMember(
				(new Accessor("owner"))
					SET_ACCESSOR_LINK(GET, (&IPedCollection<HASH::PedBone, SDK::PedBone>::getOwner))
				);
			Environment::addClass<SDK::PedBoneCollection>(PedBoneCollection);
		}

		static void UI_Text_build()
		{
			UI_Text = new Builder("UI_Text");
			UI_Text
				->setLuaAccessorFilter(
					STANDART_LUA_ACCESSOR_FILTER(SDK::UI::Text)
				)
				->setLuaDestructor(
					STANDART_LUA_DESTRUCTOR(SDK::UI::Text)
				)
				->addMember(
					SET_ENUM(UI_Text, SDK::UI::Text::Font, "Font")
				)
				->addMember(
					SET_ENUM(UI_Text, SDK::UI::Text::Alignment, "Alignment")
				)
				->setConstructor(
				(new Constructor)
					SET_METHOD_LINK(UI::Text::constructor)
					->setArgNames({ "text" })
				)
				->addMember(
				(new Accessor("x"))
					SET_ACCESSOR_LINK(GET, &UI::Text::getPosX)
					SET_ACCESSOR_LINK(SET, &UI::Text::setPosX)
				)
				->addMember(
				(new Accessor("y"))
					SET_ACCESSOR_LINK(GET, &UI::Text::getPosY)
					SET_ACCESSOR_LINK(SET, &UI::Text::setPosY)
				)
				->addMember(
				(new Accessor("font"))
					SET_ACCESSOR_LINK(GET, &UI::Text::getFont)
					SET_ACCESSOR_LINK(SET, &UI::Text::setFont)
				)
				->addMember(
				(new Accessor("scale"))
					SET_ACCESSOR_LINK(GET, &UI::Text::getScale)
					SET_ACCESSOR_LINK(SET, &UI::Text::setScale)
				)
				->addMember(
				(new Accessor("text"))
					SET_ACCESSOR_LINK(GET, &UI::Text::getText)
					SET_ACCESSOR_LINK(SET, &UI::Text::setText)
				)
				->addMember(
				(new Accessor("alignment"))
					SET_ACCESSOR_LINK(GET, &UI::Text::getAlignment)
					SET_ACCESSOR_LINK(SET, &UI::Text::setAlignment)
				)
				->addMember(
				(new Accessor("color"))
					SET_ACCESSOR_LINK(GET, &UI::Text::getColor)
					SET_ACCESSOR_LINK(SET, &UI::Text::setColor)
				)
				->addMember(
				(new Accessor("outline"))
					SET_ACCESSOR_LINK(GET, &UI::Text::isOutline)
					SET_ACCESSOR_LINK(SET, &UI::Text::setOutline)
				)
				->addMember(
				(new Accessor("shadow"))
					SET_ACCESSOR_LINK(GET, &UI::Text::isShadow)
					SET_ACCESSOR_LINK(SET, &UI::Text::setShadow)
				)
				->addMember(
				(new Method("draw"))
					SET_METHOD_LINK(static_cast<void(UI::Text::*)()>(&UI::Text::draw))
				);
			Environment::addClass<SDK::UI::Text>(UI_Text);
		}

		static void Screen_build()
		{
			Screen = new Builder("Screen");
			Screen
				->addMember(
					SET_ENUM(Screen, SDK::Screen::Effect, "Effect")
				)
				->addMember(
				(new StaticMethod("GetResolution"))
					SET_METHOD_LINK(Screen::GetResolution)
				)
				->addMember(
				(new StaticMethod("GetAspectRatio"))
					SET_METHOD_LINK(Screen::GetAspectRatio)
				)
				->addMember(
				(new StaticMethod("GetScaledHeight"))
					SET_METHOD_LINK(Screen::GetScaledHeight)
				)
				->addMember(
				(new StaticMethod("IsFadedIn"))
					SET_METHOD_LINK(Screen::IsFadedIn)
				)
				->addMember(
				(new StaticMethod("IsFadedOut"))
					SET_METHOD_LINK(Screen::IsFadedOut)
				)
				->addMember(
				(new StaticMethod("IsFadingIn"))
					SET_METHOD_LINK(Screen::IsFadingIn)
				)
				->addMember(
				(new StaticMethod("IsFadingOut"))
					SET_METHOD_LINK(Screen::IsFadingOut)
				)
				->addMember(
				(new StaticMethod("FadeIn"))
					SET_METHOD_LINK(Screen::FadeIn)
					->setArgNames({ "duration" })
				)
				->addMember(
				(new StaticMethod("FadeOut"))
					SET_METHOD_LINK(Screen::FadeOut)
					->setArgNames({ "duration" })
				)
				->addMember(
				(new StaticMethod("IsEffectActive"))
					SET_METHOD_LINK(Screen::IsEffectActive)
					->setArgNames({ "effect" })
				)
				->addMember(
				(new StaticMethod("StartEffect"))
					SET_METHOD_LINK(Screen::StartEffect)
					->setArgNames({ "effect", "duration", "false" })
					->setDefArgValues(std::make_tuple(Method::anyValue, 0, false))
				)
				->addMember(
				(new StaticMethod("StopEffect"))
					SET_METHOD_LINK(Screen::StopEffect)
					->setArgNames({ "effect" })
				)
				->addMember(
				(new StaticMethod("StopEffects"))
					SET_METHOD_LINK(Screen::StopEffects)
				)
				->addMember(
				(new StaticMethod("WorldToScreen"))
					SET_METHOD_LINK(Screen::WorldToScreen)
					->setArgNames({ "worldCoord" })
				);
			Environment::addStaticClass(Screen);
		}

		static void Native_build()
		{
			Native = new Builder("Native");
			Native
				->addMember(
				(new StaticMethod("Call"))
					->V8_setCall(Native::V8::call)
					->Lua_setCall(Native::Lua::call)
					->setArgNames({"native", "arguments..."})
				);

			for (auto const& group : GameScriptEngine::getNativeGroups())
			{
				Enum* enum_ = new Enum(group.first);
				for (auto const& native : group.second) {
					enum_->addItem(native->getName(), native->getHash());
				}

				Native->addMember(
					enum_
				);
			}

			Environment::addStaticClass(Native);
		}

		static void NativePointer_build()
		{
			NativePointer = new Builder("NativePointer");
			NativePointer
				->addMember(
				(new Accessor("integer"))
					SET_ACCESSOR_LINK(GET, &Native::Pointer::getInteger)
				)
				->addMember(
				(new Accessor("boolean"))
					SET_ACCESSOR_LINK(GET, &Native::Pointer::getBoolean)
				)
				->addMember(
				(new Accessor("double"))
					SET_ACCESSOR_LINK(GET, &Native::Pointer::getDouble)
				)
				->addMember(
				(new Accessor("string"))
					SET_ACCESSOR_LINK(GET, &Native::Pointer::getString)
				);

			Environment::addClass<SDK::Native::Pointer>(NativePointer);
		}
	};
};