#pragma once



#include "Game/IGameHook.h"
#include "Game/IGameHooked.h"
#include "Game/GameHookList.h"
#include "Utility/ISingleton.h"
#include "Utility/IDynStructure.h"



class GameEntityStructure
	: public Memory::IDynStructure<GameEntityStructure>, public IGameStaticHooked
{
public:
	enum FIELD {
		occupiedInfo,
		entityType,
		pos
	};

	static void init() {
		setFieldOffset(occupiedInfo, 0x10);
		setFieldOffset(entityType, 0x28);
	}

	GameEntityStructure(Memory::Handle base)
		: IDynStructure(base)
	{}

	bool isOccupied() {
		return getFieldValue<std::uintptr_t>(occupiedInfo) != 0;
	}

	byte getType() {
		return getFieldValue<byte>(entityType);
	}
};




template<typename T>
class IGameEntityStructure
	: public Memory::IDynStructure<T>
{
public:
	static void init() {
		IGameEntityStructure::setFieldOffset(T::FIELD::entity, 0x0);
		GameEntityStructure::firstInit();
	}

	IGameEntityStructure(Memory::Handle base)
		: Memory::IDynStructure<T>(base)
	{}

	GameEntityStructure getEntity() {
		return GameEntityStructure(
			IGameEntityStructure::getField(T::FIELD::entity)
		);
	}
};

class GamePedStructure
	: public IGameEntityStructure<GamePedStructure>, public IGameStaticHooked
{
public:
	enum FIELD {
		entity,

	};

	static void init() {
		IGameEntityStructure::init();
	}

	GamePedStructure(Memory::Handle base)
		: IGameEntityStructure(base)
	{}
};

class GameObjectStructure
	: public IGameEntityStructure<GameObjectStructure>, public IGameStaticHooked
{
public:
	enum FIELD {
		entity,

	};

	static void init() {
		IGameEntityStructure::init();
	}

	GameObjectStructure(Memory::Handle base)
		: IGameEntityStructure(base)
	{}
};

class GamePickupStructure
	: public IGameEntityStructure<GamePickupStructure>, public IGameStaticHooked
{
public:
	enum FIELD {
		entity,

	};

	static void init() {
		IGameEntityStructure::init();
	}

	GamePickupStructure(Memory::Handle base)
		: IGameEntityStructure(base)
	{}
};

class GameVehicleStructure
	: public IGameEntityStructure<GameVehicleStructure>, public IGameStaticHooked
{
public:
	enum FIELD {
		entity,

	};

	static void init() {
		IGameEntityStructure::init();
	}

	GameVehicleStructure(Memory::Handle base)
		: IGameEntityStructure(base)
	{}
};


class GameObject : public IGameStaticHooked
{
public:
	using Entity = GameEntityStructure;
	using Ped = GamePedStructure;
	using Object = GameObjectStructure;
	using Pickup = GamePickupStructure;
	using Vehicle = GameVehicleStructure;

	enum TYPE {
		VEHICLE = 3,
		PED = 4
	};

	inline static Memory::Function<uint64_t(void*)> AddressToEntity;
	inline static Memory::Function<void*(uint64_t)> EntityToAddress;
};


class GameObjectHook_Gen : public IGameHook, public ISingleton<GameObjectHook_Gen>
{
public:
	void Install()
	{
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("48 89 5c 24 ?? 48 89 74 24 ?? 57 48 83 ec 20 8b 15 ?? ?? ?? ?? 48 8b f9 48 83 c1 10 33 db"),
				&AddressToEntity
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("83 f9 ff 74 31 4c 8b 0d ?? ?? ?? ?? 44 8b c1 49 8b 41 08"),
				&EntityToAddress
			)
		);
	}
	
	static void AddressToEntity(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}
		GameObject::AddressToEntity = pattern.getResult();
	}

	static void EntityToAddress(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}
		GameObject::EntityToAddress = pattern.getResult();
	}

	void Remove()
	{
	}
};