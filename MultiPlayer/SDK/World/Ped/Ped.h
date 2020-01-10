#pragma once


#include "../Entity.h"
#include "../../Model/Model.h"
#include "../Animation.h"

namespace SDK {
	class WeaponCollection;
	class PedBoneCollection;
	class TaskInvoker;

	class Ped
		: public Entity, public Class::IExportable<Ped>
	{
	public:
		//for export
		Ped* getPersistent() override {
			return new Ped(getId());
		}

		enum Gender
		{
			Male,
			Female
		};

		enum DrivingStyle
		{
			Normal = 786603,
			IgnoreLights = 2883621,
			SometimesOvertakeTraffic = 5,
			Rushed = 1074528293,
			AvoidTraffic = 786468,
			AvoidTrafficExtremely = 6
		};
		
		enum class VehicleDrivingFlags : DWORD
		{
			None = 0,
			FollowTraffic = 1,
			YieldToPeds = 2,
			AvoidVehicles = 4,
			AvoidEmptyVehicles = 8,
			AvoidPeds = 16,
			AvoidObjects = 32,
			StopAtTrafficLights = 128,
			UseBlinkers = 256,
			AllowGoingWrongWay = 512,
			Reverse = 1024,
			AllowMedianCrossing = 262144,
			DriveBySight = 4194304,
			IgnorePathFinding = 16777216,
			TryToAvoidHighways = 536870912,
			StopAtDestination = 2147483648
		};

		enum class HelmetType : DWORD
		{
			RegularMotorcycleHelmet = 4096u,
			FiremanHelmet = 16384u,
			PilotHeadset = 32768u
		};

		enum class ParachuteLandingType
		{
			None = -1,
			Stumbling = 1,
			Rolling,
			Ragdoll
		};

		enum class ParachuteState
		{
			None = -1,
			FreeFalling,
			Deploying,
			Gliding,
			LandingOrFallingToDoom
		};

		enum class RagdollType
		{
			Normal = 0,
			StiffLegs = 1,
			NarrowLegs = 2,
			WideLegs = 3,
		};

		enum class SpeechModifier
		{
			Standard = 0,
			AllowRepeat = 1,
			Beat = 2,
			Force = 3,
			ForceFrontend = 4,
			ForceNoRepeatFrontend = 5,
			ForceNormal = 6,
			ForceNormalClear = 7,
			ForceNormalCritical = 8,
			ForceShouted = 9,
			ForceShoutedClear = 10,
			ForceShoutedCritical = 11,
			ForcePreloadOnly = 12,
			Megaphone = 13,
			Helicopter = 14,
			ForceMegaphone = 15,
			ForceHelicopter = 16,
			Interrupt = 17,
			InterruptShouted = 18,
			InterruptShoutedClear = 19,
			InterruptShoutedCritical = 20,
			InterruptNoForce = 21,
			InterruptFrontend = 22,
			InterruptNoForceFrontend = 23,
			AddBlip = 24,
			AddBlipAllowRepeat = 25,
			AddBlipForce = 26,
			AddBlipShouted = 27,
			AddBlipShoutedForce = 28,
			AddBlipInterrupt = 29,
			AddBlipInterruptForce = 30,
			ForcePreloadOnlyShouted = 31,
			ForcePreloadOnlyShoutedClear = 32,
			ForcePreloadOnlyShoutedCritical = 33,
			Shouted = 34,
			ShoutedClear = 35,
			ShoutedCritical = 36
		};

		enum class Type : int
		{
			PED_TYPE_PLAYER_0, //michael
			PED_TYPE_PLAYER_1, //franklin
			PED_TYPE_NETWORK_PLAYER, //mp character
			PED_TYPE_PLAYER_2, //trevor
			PED_TYPE_CIVMALE,
			PED_TYPE_CIVFEMALE,
			PED_TYPE_COP,
			PED_TYPE_GANG_ALBANIAN,
			PED_TYPE_GANG_BIKER_1,
			PED_TYPE_GANG_BIKER_2,
			PED_TYPE_GANG_ITALIAN,
			PED_TYPE_GANG_RUSSIAN,
			PED_TYPE_GANG_RUSSIAN_2,
			PED_TYPE_GANG_IRISH,
			PED_TYPE_GANG_JAMAICAN,
			PED_TYPE_GANG_AFRICAN_AMERICAN,
			PED_TYPE_GANG_KOREAN,
			PED_TYPE_GANG_CHINESE_JAPANESE,
			PED_TYPE_GANG_PUERTO_RICAN,
			PED_TYPE_DEALER,
			PED_TYPE_MEDIC,
			PED_TYPE_FIREMAN,
			PED_TYPE_CRIMINAL,
			PED_TYPE_BUM,
			PED_TYPE_PROSTITUTE,
			PED_TYPE_SPECIAL,
			PED_TYPE_MISSION,
			PED_TYPE_SWAT,
			PED_TYPE_ANIMAL,
			PED_TYPE_ARMY
		};

		Ped(SE::Ped id)
			: Entity(id)
		{};
		~Ped() {
			
		}

		///<summary>Gets the id of this ped.</summary>
		SE::Ped getId() {
			return Entity::getId();
		}

		///<summary>Gets the model of this ped.</summary>
		PedModel getModel() {
			return Entity::getModel();
		}

		///<summary>Gets how much money this <see cref="Ped"/> is carrying.</summary>
		uint32_t getMoney() {
			return Call(
				SE::PED::GET_PED_MONEY,
				getId()
			);
		}

		///<summary>Sets how much money this <see cref="Ped"/> is carrying.</summary>
		void setMoney(uint32_t amount) {
			Call(
				SE::PED::SET_PED_MONEY,
				getId(),
				amount
			);
		}

		///<summary>Gets the gender of this <see cref="Ped"/>.</summary>
		Gender getGender() {
			return Call(
				SE::PED::IS_PED_MALE,
				getId()
			) == TRUE ? Male : Female;
		}

		///<summary>Gets the armour of this <see cref="Ped"/> as an <see cref="uint32_t"/>.</summary>
		uint32_t getArmour() {
			return Call(
				SE::PED::GET_PED_ARMOUR,
				getId()
			);
		}

		///<summary>Sets the armour of this <see cref="Ped"/> as an <see cref="uint32_t"/>.</summary>
		void setArmour(uint32_t amount) {
			return Call(
				SE::PED::SET_PED_ARMOUR,
				getId(),
				amount
			);
		}

		///<summary>Gets a collection of all this <see cref="Ped"/>s <see cref="PedBone"/>s.</summary>
		PedBoneCollection* getBones() {
			if (m_bones == nullptr) {
				//throw ex
			}
			return m_bones;
		}

		///<summary>Ses a collection of all this <see cref="Ped"/>s <see cref="PedBone"/>s.</summary>
		void setBoneCollection(PedBoneCollection* boneCol) {
			m_bones = boneCol;
		}

		///<summary>Gets a collection of all this <see cref="Ped"/>s <see cref="Weapon"/>s.</summary>
		WeaponCollection* getWeapons() {
			if (m_weapons == nullptr) {
				//throw ex
			}
			return m_weapons;
		}

		///<summary>Ses a collection of all this <see cref="Ped"/>s <see cref="Weapon"/>s.</summary>
		void setWeaponCollection(WeaponCollection* weapCol) {
			m_weapons = weapCol;
		}

		///<summary></summary>
		TaskInvoker* getTaskInvoker() {
			if (m_taskInvoker == nullptr) {
				//throw ex
			}
			return m_taskInvoker;
		}

		///<summary></summary>
		void setTaskInvoker(TaskInvoker* invoker) {
			m_taskInvoker = invoker;
		}

		///<summary>Make <see cref="Ped"/> play the animation.</summary>
		void playAnim(ANIM::Anim animation) {
			if (!ANIM::Dict(animation.getDict()).load())
				return;

			Call(
				SE::AI::TASK_PLAY_ANIM,
				getId(),
				animation.getDict().c_str(),
				animation.getName().c_str(),
				animation.getInSpeed(),
				animation.getOutSpeed(),
				animation.getDuration(),
				(int)animation.getFlags(),
				animation.getPlaybackRate(),
				FALSE, FALSE, FALSE
			);
		}

		static SE::Ped GetLocalPlayerPed()
		{
			return Call(
				SE::PLAYER::GET_PLAYER_PED,
				Call(SE::PLAYER::PLAYER_ID)
			);
		}
	private:
		WeaponCollection* m_weapons = nullptr;
		PedBoneCollection* m_bones = nullptr;
		TaskInvoker* m_taskInvoker = nullptr;
	};
};