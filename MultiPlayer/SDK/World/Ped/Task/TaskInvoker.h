#pragma once

/*
	Regex replace all:
	{
		Source:			public void (\w+)\((.*)\)\n{\n\tFunction\.Call\(Hash\.(\w+),(.+)\)
		Destinition:	void $1($2)\n{\n\tcallNative(\n\t\tSE::TASK::$3,\n\t\t$4\n\t)
	}

	{
		Source:			_ped\.Handle	
		Destinition:	getOwner()->getId()
	}

	{
		Source:			ped\.Handle
		Destinition:	ped->getId()
	}

	{
		Source:			(\w+)\.([XYZ])
		Destinition:	$1.get$2()
	}

	{
		Source:			(\w+)\.Handle
		Destinition:	$1->getId()
	}

	Other:
		Vector3			=> Vector3D
		Ped ped			=> Ped *ped
		Entity target	=> Entity *target
*/


#include "../Ped.h"
#include "../../Vehicle/Vehicle.h"


namespace SDK {
	enum class FiringPattern : DWORD
	{
		Default,
		FullAuto = 3337513804u,
		BurstFire = 3607063905u,
		BurstInCover = 40051185u,
		BurstFireDriveby = 3541198322u,
		FromGround = 577037782u,
		DelayFireByOneSec = 2055493265u,
		SingleShot = 1566631136u,
		BurstFirePistol = 2685983626u,
		BurstFireSMG = 3507334638u,
		BurstFireRifle = 2624893958u,
		BurstFireMG = 3044263348u,
		BurstFirePumpShotGun = 12239771u,
		BurstFireHeli = 2437838959u,
		BurstFireMicro = 1122960381u,
		BurstFireBursts = 1122960381u,
		BurstFireTank = 3804904049u
	};
	
	enum class EnterVehicleFlags : DWORD
	{
		None = 0,
		WarpToDoor = 2,
		AllowJacking = 8,
		WarpIn = 16,
		EnterFromOppositeSide = 262144,
		OnlyOpenDoor = 524288,
	};

	enum class LeaveVehicleFlags : DWORD
	{
		None = 0,
		WarpOut = 16,
		LeaveDoorOpen = 256,
		BailOut = 4096
	};

	class TaskInvoker : public Class::IExportable<TaskInvoker>
	{
	public:
		//for export
		TaskInvoker* getPersistent() override {
			return TaskInvoker::constructor(getOwner());
		}

		static TaskInvoker* constructor(Ped* owner) {
			return new TaskInvoker(owner);
		}

		TaskInvoker(Ped* owner)
			: m_owner(owner)
		{}
		
		///<summary></summary>
		void AchieveHeading(float heading, int timeout = 0)
		{
			Call(
				SE::AI::TASK_ACHIEVE_HEADING,
				getOwner()->getId(), heading, timeout
			);
		}

		
		///<summary></summary>
		void AimAt(Entity* target, int duration)
		{
			Call(
				SE::AI::TASK_AIM_GUN_AT_ENTITY,
				getOwner()->getId(), target->getId(), duration, 0
			);
		}

		
		///<summary></summary>
		void AimAt(Vector3D target, int duration)
		{
			Call(
				SE::AI::TASK_AIM_GUN_AT_COORD,
				getOwner()->getId(), target.getX(), target.getY(), target.getZ(), duration, 0, 0
			);
		}

		
		///<summary></summary>
		void Arrest(Ped* ped)
		{
			Call(
				SE::AI::TASK_ARREST_PED,
				getOwner()->getId(), ped->getId()
			);
		}

		
		///<summary></summary>
		void ChatTo(Ped* ped)
		{
			Call(
				SE::AI::TASK_CHAT_TO_PED,
				getOwner()->getId(), ped->getId(), 16, 0.f, 0.f, 0.f, 0.f, 0.f
			);
		}

		
		///<summary></summary>
		void Jump()
		{
			Call(
				SE::AI::TASK_JUMP,
				getOwner()->getId(), true
			);
		}

		
		///<summary></summary>
		void Climb()
		{
			Call(
				SE::AI::TASK_CLIMB,
				getOwner()->getId(), true
			);
		}

		
		///<summary></summary>
		void ClimbLadder()
		{
			Call(
				SE::AI::TASK_CLIMB_LADDER,
				getOwner()->getId(), 1
			);
		}

		
		///<summary></summary>
		void Cower(int duration)
		{
			Call(
				SE::AI::TASK_COWER,
				getOwner()->getId(), duration
			);
		}

		
		///<summary></summary>
		void ChaseWithGroundVehicle(Ped* target)
		{
			Call(
				SE::AI::TASK_VEHICLE_CHASE,
				getOwner()->getId(), target->getId()
			);
		}

		
		///<summary></summary>
		void ChaseWithHelicopter(Ped* target, Vector3D offset)
		{
			Call(
				SE::AI::TASK_HELI_CHASE,
				getOwner()->getId(), target->getId(), offset.getX(), offset.getY(), offset.getZ()
			);
		}

		
		///<summary></summary>
		void ChaseWithPlane(Ped* target, Vector3D offset)
		{
			Call(
				SE::AI::TASK_PLANE_CHASE,
				getOwner()->getId(), target->getId(), offset.getX(), offset.getY(), offset.getZ()
			);
		}

		
		///<summary></summary>
		void CruiseWithVehicle(Vehicle* vehicle, float speed, Ped::DrivingStyle style = Ped::DrivingStyle::Normal)
		{
			Call(
				SE::AI::TASK_VEHICLE_DRIVE_WANDER,
				getOwner()->getId(), vehicle->getId(), speed, style
			);
		}

		
		///<summary></summary>
		void DriveTo(Vehicle* vehicle, Vector3D target, float radius, float speed, Ped::DrivingStyle style = Ped::DrivingStyle::Normal)
		{
			Call(
				SE::AI::TASK_VEHICLE_DRIVE_TO_COORD_LONGRANGE,
				getOwner()->getId(), vehicle->getId(), target.getX(), target.getY(), target.getZ(), speed, style, radius
			);
		}

		
		///<summary></summary>
		void EnterAnyVehicle(Vehicle::Seat seat = Vehicle::Seat::Any, int timeout = -1, float speed = 1.f, EnterVehicleFlags flag = EnterVehicleFlags::None)
		{
			Call(
				SE::AI::TASK_ENTER_VEHICLE,
				getOwner()->getId(), 0, timeout, (int)seat, speed, (int)flag, 0
			);
		}

		
		///<summary></summary>
		void EnterVehicle(Vehicle* vehicle, Vehicle::Seat seat = Vehicle::Seat::Any, int timeout = -1, float speed = 1.f, EnterVehicleFlags flag = EnterVehicleFlags::None)
		{
			Call(
				SE::AI::TASK_ENTER_VEHICLE,
				getOwner()->getId(), vehicle->getId(), timeout, (int)seat, speed, (int)flag, 0
			);
		}

		
		///<summary></summary>
		void FightAgainst(Ped* target)
		{
			Call(
				SE::AI::TASK_COMBAT_PED,
				getOwner()->getId(), target->getId(), 0, 16
			);
		}

		
		///<summary></summary>
		void FightAgainst(Ped* target, int duration)
		{
			Call(
				SE::AI::TASK_COMBAT_PED_TIMED,
				getOwner()->getId(), target->getId(), duration, 0
			);
		}

		
		///<summary></summary>
		void FightAgainstHatedTargets(float radius)
		{
			Call(
				SE::AI::TASK_COMBAT_HATED_TARGETS_AROUND_PED,
				getOwner()->getId(), radius, 0
			);
		}

		
		///<summary></summary>
		void FightAgainstHatedTargets(float radius, int duration)
		{
			Call(
				SE::AI::TASK_COMBAT_HATED_TARGETS_AROUND_PED_TIMED,
				getOwner()->getId(), radius, duration, 0
			);
		}

		
		///<summary></summary>
		void FleeFrom(Ped* ped, int duration = -1)
		{
			Call(
				SE::AI::TASK_SMART_FLEE_PED,
				getOwner()->getId(), ped->getId(), 100.f, duration, 0, 0
			);
		}

		
		///<summary></summary>
		void FleeFrom(Vector3D position, int duration = -1)
		{
			Call(
				SE::AI::TASK_SMART_FLEE_COORD,
				getOwner()->getId(), position.getX(), position.getY(), position.getZ(), 100.f, duration, 0, 0
			);
		}

		
		///<summary></summary>
		void FollowToOffsetFromEntity(Entity* target, Vector3D offset, float movementSpeed, int timeout = -1, float distanceToFollow = 10.f, bool persistFollowing = true)
		{
			Call(
				SE::AI::TASK_FOLLOW_TO_OFFSET_OF_ENTITY,
				getOwner()->getId(), target->getId(), offset.getX(), offset.getY(), offset.getZ(), movementSpeed, timeout, distanceToFollow, persistFollowing
			);
		}

		
		///<summary></summary>
		void GoTo(Entity* target, Vector3D offset = Vector3D(), int timeout = -1)
		{
			Call(
				SE::AI::TASK_GOTO_ENTITY_OFFSET_XY,
				getOwner()->getId(), target->getId(), timeout, offset.getX(), offset.getY(), offset.getZ(), 1.f, true
			);
		}

		
		///<summary></summary>
		void GoTo(Vector3D position, int timeout = -1)
		{
			Call(
				SE::AI::TASK_FOLLOW_NAV_MESH_TO_COORD,
				getOwner()->getId(), position.getX(), position.getY(), position.getZ(), 1.f, timeout, 0.f, 0, 0.f
			);
		}

		
		///<summary></summary>
		void GoStraightTo(Vector3D position, int timeout = -1, float targetHeading = 0.f, float distanceToSlide = 0.f)
		{
			Call(
				SE::AI::TASK_GO_STRAIGHT_TO_COORD,
				getOwner()->getId(), position.getX(), position.getY(), position.getZ(), 1.f, timeout, targetHeading, distanceToSlide
			);
		}

		
		///<summary></summary>
		void GuardCurrentPosition()
		{
			Call(
				SE::AI::TASK_GUARD_CURRENT_POSITION,
				getOwner()->getId(), 15.f, 10.f, true
			);
		}

		
		///<summary></summary>
		void HandsUp(int duration)
		{
			Call(
				SE::AI::TASK_HANDS_UP,
				getOwner()->getId(), duration, 0, -1, false
			);
		}

		
		///<summary></summary>
		void LeaveVehicle(LeaveVehicleFlags flags = LeaveVehicleFlags::None)
		{
			Call(
				SE::AI::TASK_LEAVE_ANY_VEHICLE,
				getOwner()->getId(), 0, (int)flags
			);
		}

		
		///<summary></summary>
		void LeaveVehicle(Vehicle* vehicle, LeaveVehicleFlags flags)
		{
			Call(
				SE::AI::TASK_LEAVE_VEHICLE,
				getOwner()->getId(), vehicle->getId(), (int)flags
			);
		}

		
		///<summary></summary>
		void LookAt(Entity* target, int duration = -1)
		{
			Call(
				SE::AI::TASK_LOOK_AT_ENTITY,
				getOwner()->getId(), target->getId(), duration, 0, 2
			);
		}

		
		///<summary></summary>
		void LookAt(Vector3D position, float duration = -1.0)
		{
			Call(
				SE::AI::TASK_LOOK_AT_COORD,
				getOwner()->getId(), position.getX(), position.getY(), position.getZ(), duration, 0, 2
			);
		}

		
		///<summary></summary>
		void ParachuteTo(Vector3D position)
		{
			Call(
				SE::AI::TASK_PARACHUTE_TO_TARGET,
				getOwner()->getId(), position.getX(), position.getY(), position.getZ()
			);
		}

		
		///<summary></summary>
		void ParkVehicle(Vehicle* vehicle, Vector3D position, float heading, float radius = 20.0f, bool keepEngineOn = false)
		{
			Call(
				SE::AI::TASK_VEHICLE_PARK,
				getOwner()->getId(), vehicle->getId(), position.getX(), position.getY(), position.getZ(), heading, 1, radius, keepEngineOn
			);
		}

		
		///<summary></summary>
		void RappelFromHelicopter()
		{
			Call(
				SE::AI::TASK_RAPPEL_FROM_HELI,
				getOwner()->getId(), 0x41200000
			);
		}

		
		///<summary></summary>
		void ReactAndFlee(Ped* ped)
		{
			Call(
				SE::AI::TASK_REACT_AND_FLEE_PED,
				getOwner()->getId(), ped->getId()
			);
		}

		
		///<summary></summary>
		void ReloadWeapon()
		{
			Call(
				SE::AI::TASK_RELOAD_WEAPON,
				getOwner()->getId(), true
			);
		}

		
		///<summary></summary>
		void ShootAt(Ped* target, int duration = -1, FiringPattern pattern = FiringPattern::Default)
		{
			Call(
				SE::AI::TASK_SHOOT_AT_ENTITY,
				getOwner()->getId(), target->getId(), duration, (SE::Hash)pattern
			);
		}

		
		///<summary></summary>
		void ShootAt(Vector3D position, int duration = -1, FiringPattern pattern = FiringPattern::Default)
		{
			Call(
				SE::AI::TASK_SHOOT_AT_COORD,
				getOwner()->getId(), position.getX(), position.getY(), position.getZ(), duration, (SE::Hash)pattern
			);
		}

		
		///<summary></summary>
		void Skydive()
		{
			Call(
				SE::AI::TASK_SKY_DIVE,
				getOwner()->getId()
			);
		}

		
		///<summary></summary>
		void SlideTo(Vector3D position, float heading)
		{
			Call(
				SE::AI::TASK_PED_SLIDE_TO_COORD,
				getOwner()->getId(), position.getX(), position.getY(), position.getZ(), heading, 0.7f
			);
		}

		
		///<summary></summary>
		void StandStill(int duration)
		{
			Call(
				SE::AI::TASK_STAND_STILL,
				getOwner()->getId(), duration
			);
		}

		
		///<summary></summary>
		void StartScenario(std::string name, Vector3D position)
		{
			Call(
				SE::AI::TASK_START_SCENARIO_AT_POSITION,
				getOwner()->getId(), name.c_str(), position.getX(), position.getY(), position.getZ(), 0.f, 0, 0, 1
			);
		}

		
		///<summary></summary>
		void SwapWeapon()
		{
			Call(
				SE::AI::TASK_SWAP_WEAPON,
				getOwner()->getId(), false
			);
		}

		
		///<summary></summary>
		void TurnTo(Entity* target, int duration = -1)
		{
			Call(
				SE::AI::TASK_TURN_PED_TO_FACE_ENTITY,
				getOwner()->getId(), target->getId(), duration
			);
		}

		
		///<summary></summary>
		void TurnTo(Vector3D position, int duration = -1)
		{
			Call(
				SE::AI::TASK_TURN_PED_TO_FACE_COORD,
				getOwner()->getId(), position.getX(), position.getY(), position.getZ(), duration
			);
		}

		
		///<summary></summary>
		void UseParachute()
		{
			Call(
				SE::AI::TASK_PARACHUTE,
				getOwner()->getId(), true
			);
		}

		
		///<summary></summary>
		void UseMobilePhone()
		{
			Call(
				SE::AI::TASK_USE_MOBILE_PHONE,
				getOwner()->getId(), true
			);
		}

		
		///<summary></summary>
		void UseMobilePhone(int duration)
		{
			Call(
				SE::AI::TASK_USE_MOBILE_PHONE_TIMED,
				getOwner()->getId(), duration
			);
		}

		
		///<summary></summary>
		void PutAwayParachute()
		{
			Call(
				SE::AI::TASK_PARACHUTE,
				getOwner()->getId(), false
			);
		}

		
		///<summary></summary>
		void PutAwayMobilePhone()
		{
			Call(
				SE::AI::TASK_USE_MOBILE_PHONE,
				getOwner()->getId(), false
			);
		}

		
		///<summary></summary>
		void VehicleChase(Ped* target)
		{
			Call(
				SE::AI::TASK_VEHICLE_CHASE,
				getOwner()->getId(), target->getId()
			);
		}

		
		///<summary></summary>
		void VehicleShootAtPed(Ped* target)
		{
			Call(
				SE::AI::TASK_VEHICLE_SHOOT_AT_PED,
				getOwner()->getId(), target->getId(), 20.f
			);
		}

		
		///<summary></summary>
		void Wait(int duration)
		{
			Call(
				SE::AI::TASK_PAUSE,
				getOwner()->getId(), duration
			);
		}

		
		///<summary></summary>
		void WanderAround()
		{
			Call(
				SE::AI::TASK_WANDER_STANDARD,
				getOwner()->getId(), 0.f, 0
			);
		}

		
		///<summary></summary>
		void WanderAround(Vector3D position, float radius)
		{
			Call(
				SE::AI::TASK_WANDER_IN_AREA,
				getOwner()->getId(), position.getX(), position.getY(), position.getZ(), radius, 0.f, 0.f
			);
		}

		
		///<summary></summary>
		void WarpIntoVehicle(Vehicle* vehicle, Vehicle::Seat seat)
		{
			Call(
				SE::AI::TASK_WARP_PED_INTO_VEHICLE,
				getOwner()->getId(), vehicle->getId(), (int)seat
			);
		}

		
		///<summary></summary>
		void WarpOutOfVehicle(Vehicle* vehicle)
		{
			Call(
				SE::AI::TASK_LEAVE_VEHICLE,
				getOwner()->getId(), vehicle->getId(), 16
			);
		}

		
		///<summary></summary>
		void ClearAll()
		{
			Call(
				SE::AI::CLEAR_PED_TASKS,
				getOwner()->getId()
			);
		}

		
		///<summary></summary>
		void ClearAllImmediately()
		{
			Call(
				SE::AI::CLEAR_PED_TASKS_IMMEDIATELY,
				getOwner()->getId()
			);
		}

		
		///<summary></summary>
		void ClearLookAt()
		{
			Call(
				SE::AI::TASK_CLEAR_LOOK_AT,
				getOwner()->getId()
			);
		}

		
		///<summary></summary>
		void ClearSecondary()
		{
			Call(
				SE::AI::CLEAR_PED_SECONDARY_TASK,
				getOwner()->getId()
			);
		}

		
		///<summary></summary>
		void ClearAnimation(std::string animSet, std::string animName)
		{
			Call(
				SE::AI::STOP_ANIM_TASK,
				getOwner()->getId(), animSet.c_str(), animName.c_str(), -4.f
			);
		}

		///<summary></summary>
		Ped* getOwner() {
			return m_owner;
		}
	private:
		Ped* m_owner = nullptr;
	};
};