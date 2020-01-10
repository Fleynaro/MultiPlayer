#pragma once


#include "../../../NativeCaller.h"
#include "../Ped.h"
#include "WeaponHashes.h"
#include "../../../Model/Model.h"
#include "../../ICollection.h"

namespace SDK {
	class Weapon : public Class::IExportable<Weapon>
	{
	public:
		//for export
		Weapon* getPersistent() override {
			return Weapon::constructor(getHash(), getOwner());
		}

		static Weapon* constructor(HASH::Weapon hash, Ped* owner) {
			return new Weapon(hash, owner);
		}

		enum class Group : DWORD
		{
			Unarmed = 2685387236u,
			Melee = 3566412244u,
			Pistol = 416676503u,
			SMG = 3337201093u,
			AssaultRifle = 970310034u,
			DigiScanner = 3539449195u,
			FireExtinguisher = 4257178988u,
			MG = 1159398588u,
			NightVision = 3493187224u,
			Parachute = 431593103u,
			Shotgun = 860033945u,
			Sniper = 3082541095u,
			Stungun = 690389602u,
			Heavy = 2725924767u,
			Thrown = 1548507267u,
			PetrolCan = 1595662460u
		};

		Weapon(SE::Weapon hash, Ped* owner = nullptr)
			: m_hash(HASH::Weapon(hash)), m_owner(owner)
		{}
		Weapon(HASH::Weapon hash, Ped* owner = nullptr)
			: Weapon(SE::Weapon(hash), owner)
		{}

		///<summary></summary>
		bool isPresent() {
			if (getOwner() == nullptr)
				return false;
			if (isUnarmed())
				return true;

			return Call(
				SE::WEAPON::HAS_PED_GOT_WEAPON,
				getOwner()->getId(),
				(SE::Weapon)getHash(),
				FALSE
			) == TRUE;
		}

		///<summary></summary>
		bool isUnarmed() {
			return getHash() == HASH::Weapon::Unarmed;
		}

		///<summary></summary>
		bool isValid() {
			return (Model::Hash)Call(
				SE::WEAPON::IS_WEAPON_VALID,
				(SE::Weapon)getHash()
			) == TRUE;
		}

		///<summary></summary>
		Model getModel() {
			return (Model::Hash)Call(
				SE::WEAPON::GET_WEAPONTYPE_MODEL,
				(SE::Weapon)getHash()
			);
		}

		///<summary></summary>
		Group getGroup() {
			return (Group)Call(
				SE::WEAPON::GET_WEAPONTYPE_GROUP,
				(SE::Weapon)getHash()
			);
		}

		///<summary></summary>
		uint32_t getAmmo() {
			if (isUnarmed())
				return 1;

			if (!isPresent())
				return 0;

			return Call(
				SE::WEAPON::GET_AMMO_IN_PED_WEAPON,
				getOwner()->getId(),
				(SE::Weapon)getHash()
			);
		}

		///<summary></summary>
		void setAmmo(uint32_t amount) {
			if (isUnarmed())
				return;

			if (isPresent())
			{
				Call(
					SE::WEAPON::SET_PED_AMMO,
					getOwner()->getId(),
					(SE::Weapon)getHash(),
					amount
				);
			}
			else
			{
				Call(
					SE::WEAPON::GIVE_WEAPON_TO_PED,
					getOwner()->getId(),
					(SE::Weapon)getHash(),
					amount,
					FALSE, FALSE
				);
			}
		}

		///<summary></summary>
		uint32_t getAmmoInClip() {
			if (isUnarmed())
				return 1;

			if (!isPresent())
				return 0;

			int amount = 0;
			Call(
				SE::WEAPON::GET_AMMO_IN_CLIP,
				getOwner()->getId(),
				(SE::Weapon)getHash(),
				&amount
			);
			return (uint32_t)amount;
		}

		///<summary></summary>
		void setAmmoInClip(uint32_t amount) {
			if (isUnarmed())
				return;

			if (isPresent())
			{
				Call(
					SE::WEAPON::SET_AMMO_IN_CLIP,
					getOwner()->getId(),
					(SE::Weapon)getHash(),
					amount
				);
			}
			else
			{
				Call(
					SE::WEAPON::GIVE_WEAPON_TO_PED,
					getOwner()->getId(),
					(SE::Weapon)getHash(),
					amount,
					FALSE, FALSE
				);
			}
		}

		///<summary></summary>
		uint32_t getMaxAmmo() {
			if (isUnarmed())
				return 1;

			int amount = 0;
			Call(
				SE::WEAPON::GET_MAX_AMMO,
				getOwner()->getId(),
				(SE::Weapon)getHash(),
				&amount
			);
			return (uint32_t)amount;
		}

		///<summary></summary>
		uint32_t getMaxAmmoInClip() {
			if (isUnarmed())
				return 1;

			return Call(
				SE::WEAPON::GET_MAX_AMMO_IN_CLIP,
				getOwner()->getId(),
				(SE::Weapon)getHash(),
				FALSE
			);
		}

		///<summary></summary>
		uint32_t getDefaultClipSize() {
			return Call(
				SE::WEAPON::GET_WEAPON_CLIP_SIZE,
				(SE::Weapon)getHash()
			);
		}

		///<summary></summary>
		void setInfiniteAmmo(bool state) {
			return Call(
				SE::WEAPON::SET_PED_INFINITE_AMMO,
				getOwner()->getId(),
				(SE::Weapon)getHash(),
				state
			);
		}

		///<summary></summary>
		void setInfiniteAmmoClip(bool state) {
			return Call(
				SE::WEAPON::SET_PED_INFINITE_AMMO_CLIP,
				getOwner()->getId(),
				state
			);
		}

		bool canUseOnParachute() {
			return Call(
				SE::WEAPON::CAN_USE_WEAPON_ON_PARACHUTE,
				(SE::Weapon)getHash()
			);
		}

		///<summary></summary>
		HASH::Weapon getHash() {
			return m_hash;
		}

		///<summary></summary>
		Ped* getOwner() {
			return m_owner;
		}
	private:
		HASH::Weapon m_hash;
		Ped *m_owner = nullptr;
	};




	class WeaponCollection
		: public IPedCollection<HASH::Weapon, Weapon>, public Class::IExportable<WeaponCollection>
	{
	public:
		//for export
		WeaponCollection* getPersistent() override {
			return WeaponCollection::constructor(getOwner());
		}

		static WeaponCollection* constructor(Ped* owner) {
			return new WeaponCollection(owner);
		}

		WeaponCollection(Ped* owner)
			: IPedCollection(owner)
		{}
		
		///<summary></summary>
		Weapon* createItem(HASH::Weapon hash) override {
			return new Weapon(hash, getOwner());
		}

		///<summary></summary>
		bool hasItem(HASH::Weapon hash) override {
			auto weapon = Weapon(hash, getOwner());
			return hasWeapon(&weapon);
		}

		///<summary></summary>
		bool hasWeapon(Weapon* weapon) {
			return weapon->isPresent();
		}

		///<summary></summary>
		Weapon* getCurrent() {
			SE::Hash currentWeapon = 0;
			Call(
				SE::WEAPON::GET_CURRENT_PED_WEAPON,
				getOwner()->getId(),
				&currentWeapon,
				TRUE
			);
			
			auto hash = HASH::Weapon(currentWeapon);
			return getItem(hash);
		}

		///<summary></summary>
		void give(HASH::Weapon hash, int ammo, bool equipNow = true, bool isAmmoLoaded = true) {
			auto weapon = getItem(hash);
			if (weapon == nullptr)
			{
				Call(
					SE::WEAPON::GIVE_WEAPON_TO_PED,
					getOwner()->getId(),
					(SE::Hash)hash,
					ammo, equipNow, isAmmoLoaded
				);
			}
			else {
				select(weapon);
			}
		}

		///<summary></summary>
		void select(HASH::Weapon hash) {
			auto weapon = getItem(hash);
			if (weapon == nullptr)
				return;
			select(weapon);
		}

		///<summary></summary>
		void select(Weapon *weapon) {
			if (weapon != getCurrent())
				return;

			Call(
				SE::WEAPON::SET_CURRENT_PED_WEAPON,
				getOwner()->getId(),
				(SE::Hash)weapon->getHash(),
				TRUE
			);
		}

		///<summary></summary>
		void drop() {
			Call(
				SE::WEAPON::SET_PED_DROPS_WEAPON,
				getOwner()->getId()
			);
		}

		///<summary></summary>
		void remove(HASH::Weapon hash) {
			if (hasItem(hash)) {
				Call(
					SE::WEAPON::REMOVE_WEAPON_FROM_PED,
					getOwner()->getId(),
					(SE::Hash)hash
				);
			}
		}

		///<summary></summary>
		void removeAll() {
			Call(
				SE::WEAPON::REMOVE_ALL_PED_WEAPONS,
				getOwner()->getId(),
				TRUE
			);
		}
	};
};