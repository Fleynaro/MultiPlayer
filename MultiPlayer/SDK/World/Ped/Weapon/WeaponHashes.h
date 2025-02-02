#pragma once

#include "main.h"

namespace SDK::HASH {
	enum class Weapon : DWORD
	{
		Knife = 2578778090u,
		Nightstick = 1737195953u,
		Hammer = 1317494643u,
		Bat = 2508868239u,
		GolfClub = 1141786504u,
		Crowbar = 2227010557u,
		Bottle = 4192643659u,
		SwitchBlade = 3756226112u,
		Pistol = 453432689u,
		CombatPistol = 1593441988u,
		APPistol = 584646201u,
		Pistol50 = 2578377531u,
		FlareGun = 1198879012u,
		MarksmanPistol = 3696079510u,
		Revolver = 3249783761u,
		MicroSMG = 324215364u,
		SMG = 736523883u,
		AssaultSMG = 4024951519u,
		CombatPDW = 171789620u,
		AssaultRifle = 3220176749u,
		CarbineRifle = 2210333304u,
		AdvancedRifle = 2937143193u,
		CompactRifle = 1649403952u,
		MG = 2634544996u,
		CombatMG = 2144741730u,
		PumpShotgun = 487013001u,
		SawnOffShotgun = 2017895192u,
		AssaultShotgun = 3800352039u,
		BullpupShotgun = 2640438543u,
		DoubleBarrelShotgun = 4019527611u,
		StunGun = 911657153u,
		SniperRifle = 100416529u,
		HeavySniper = 205991906u,
		GrenadeLauncher = 2726580491u,
		GrenadeLauncherSmoke = 1305664598u,
		RPG = 2982836145u,
		Minigun = 1119849093u,
		Grenade = 2481070269u,
		StickyBomb = 741814745u,
		SmokeGrenade = 4256991824u,
		BZGas = 2694266206u,
		Molotov = 615608432u,
		FireExtinguisher = 101631238u,
		PetrolCan = 883325847u,
		SNSPistol = 3218215474u,
		SpecialCarbine = 3231910285u,
		HeavyPistol = 3523564046u,
		BullpupRifle = 2132975508u,
		HomingLauncher = 1672152130u,
		ProximityMine = 2874559379u,
		Snowball = 126349499u,
		VintagePistol = 137902532u,
		Dagger = 2460120199u,
		Firework = 2138347493u,
		Musket = 2828843422u,
		MarksmanRifle = 3342088282u,
		HeavyShotgun = 984333226u,
		Gusenberg = 1627465347u,
		Hatchet = 4191993645u,
		Railgun = 1834241177u,
		Unarmed = 2725352035u,
		KnuckleDuster = 3638508604u,
		Machete = 3713923289u,
		MachinePistol = 3675956304u,
		Flashlight = 2343591895u,
		Ball = 600439132u,
		Flare = 1233104067u,
		NightVision = 2803906140u,
		Parachute = 4222310262u,
		SweeperShotgun = 317205821u,
		BattleAxe = 3441901897u,
		CompactGrenadeLauncher = 125959754u,
		MiniSMG = 3173288789u,
		PipeBomb = 3125143736u,
		PoolCue = 2484171525u,
		Wrench = 419712736u
	};

	enum class VehicleWeapon : int
	{
		Invalid = -1,
		Tank = 1945616459,
		SpaceRocket = -123497569,
		PlaneRocket = -821520672,
		PlayerLaser = -268631733,
		PlayerBullet = 1259576109,
		PlayerBuzzard = 1186503822,
		PlayerHunter = -1625648674,
		PlayerLazer = -494786007,
		EnemyLaser = 1566990507,
		SearchLight = -844344963,
		Radar = -764006018
	};
};
