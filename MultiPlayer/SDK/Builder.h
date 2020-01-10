#pragma once


#include "API.h"
#include "Model/Model.h"
#include "World/Ped/Ped.h"
#include "World/Ped/Weapon/Weapon.h"


namespace SDK {

	class CREATE
	{
	public:
		///<summary></summary>
		static Ped* PED_Test(Vector3D pos, float heading = 0.0)
		{
			return CREATE::PED(Ped::Type::PED_TYPE_MISSION, PedModel(HASH::Ped::Trevor), pos, heading, true);
		}

		///<summary></summary>
		static Ped* MP_Player(PedModel model, Vector3D pos, float heading = 0.0)
		{
			return CREATE::PED(Ped::Type::PED_TYPE_NETWORK_PLAYER, model, pos, heading, true);
		}

		///<summary></summary>
		static Ped* PED(PedModel model, Vector3D pos, float heading = 0.0, bool weapon = true)
		{
			return CREATE::PED(Ped::Type::PED_TYPE_MISSION, model, pos, heading, weapon);
		}

		///<summary></summary>
		static Ped* PED(Ped::Type type, PedModel model, Vector3D pos, float heading = 0.0, bool weapon = true)
		{
			if (!model.load()) {
				return nullptr;
			}
			return CREATE::PED(type, model.getHash(), pos, heading, weapon);
		}

		///<summary></summary>
		static Ped* PED(Ped::Type type, SE::Hash model, Vector3D pos, float heading = 0.0, bool weapon = true)
		{
			auto ped = Call(
				SE::PED::CREATE_PED,
				(int)type,
				model,
				pos.getX(), pos.getY(), pos.getZ(),
				heading,
				FALSE, FALSE
			);
			if (!ped) {
				//throw ex
				return nullptr;
			}
			return CREATE::PED(
				ped,
				weapon
			);
		}

		///<summary></summary>
		static Ped* PED_Random(Vector3D pos, bool weapon = true)
		{
			auto ped = Call(
				SE::PED::CREATE_RANDOM_PED,
				pos.getX(), pos.getY(), pos.getZ()
			);
			if (!ped) {
				//throw ex
				return nullptr;
			}
			return CREATE::PED(
				ped,
				weapon
			);
		}

		///<summary></summary>
		static Ped* PED_LocalPlayer()
		{
			return CREATE::PED(
				Ped::GetLocalPlayerPed(),
				true
			);
		}

		///<summary></summary>
		static Ped* PED(SE::Ped id, bool weapon = true)
		{
			auto ped = new SDK::Ped(id);

			if (weapon)
			{
				ped->setWeaponCollection(
					new SDK::WeaponCollection(ped)
				);
				ped->setBoneCollection(
					new SDK::PedBoneCollection(ped)
				);
				ped->setTaskInvoker(
					new SDK::TaskInvoker(ped)
				);
			}

			return ped;
		}

		///<summary>Create a test vehicle</summary>
		static Vehicle* VEHICLE_Test(Vector3D pos, float heading = 0.0)
		{
			return CREATE::VEHICLE(
				VehicleModel(
					Call(
						SE::GAMEPLAY::GET_HASH_KEY,
						"BULLET"
					)
				),
				pos,
				heading
			);
		}

		///<summary>Create a vehicle by vehicle model</summary>
		static Vehicle* VEHICLE(VehicleModel model, Vector3D pos, float heading = 0.0)
		{
			if (!model.load()) {
				return nullptr;
			}
			return CREATE::VEHICLE(model.getHash(), pos, heading);
		}

		///<summary></summary>
		static Vehicle* VEHICLE(SE::Hash model, Vector3D pos, float heading = 0.0)
		{
			auto vehicle = Call(
				SE::VEHICLE::CREATE_VEHICLE,
				model,
				pos.getX(), pos.getY(), pos.getZ(),
				heading,
				TRUE, TRUE
			);
			if (!vehicle) {
				//throw ex
				return nullptr;
			}

			return CREATE::VEHICLE(
				vehicle
			);
		}

		///<summary></summary>
		static Vehicle* VEHICLE(SE::Vehicle id)
		{
			auto vehicle = new SDK::Vehicle(id);
			return vehicle;
		}
	};
};

namespace SDK::DESTROY {

};