#pragma once




#include "Game/IGameHook.h"
#include "Game/IGameHooked.h"
#include "Game/GameHookList.h"
#include "Game/GameStructure.h"
#include "Game/GameIterator.h"
#include "Utility/ISingleton.h"
#include "Utility/IDynStructure.h"



//Game pool interface
class IGamePool
{
public:
	//current count of items
	virtual uint32_t getCount() = 0;
	//max possible count of items
	virtual uint32_t getMaxCount() = 0;
	//size of a item in bytes
	virtual uint32_t getItemSize() = 0;
	//handle of the pool begin
	virtual Memory::Handle getData() = 0;
};






//Game pool iterator interface
template<typename T>
class IGamePoolIterator : public IGameIterator<T>
{
protected:
	int m_cur = 0;
	IGamePool* m_pool = nullptr;
	
	//get an item in defined steps
	inline T* add(int n, bool change = true) override
	{
		static std::size_t
			itemSize = m_pool->getItemSize();
		if (change)
			m_cur += n;
		return Memory::Handle(this->m_elem).add(n * itemSize).as<T*>();
	}

	//find the next first valid item, otherwise end
	inline T* increment() override
	{
		static std::size_t
			maxCount = m_pool->getMaxCount();

		int cur = m_cur + 1;
		while (cur < maxCount) {
			if (isItemValid(cur)) {
				return add(cur - m_cur);
			}
			cur++;
		}

		//end
		return getItemById(maxCount).as<T*>();
	}

	//find the previous first valid item, otherwise end
	inline T* decrement() override
	{
		int cur = m_cur - 1;
		while (cur >= 0) {
			if (isItemValid(cur)) {
				return add(cur - m_cur);
			}
			cur--;
		}

		//before begin
		return getItemById(-1).as<T*>();
	}

	//check item exist(valid)
	virtual inline bool isItemValid(std::size_t i) = 0;

	inline Memory::Handle getItemById(std::size_t i) {
		return m_pool->getData().add(m_pool->getItemSize() * i);
	}
public:
	IGamePoolIterator(T * elem = nullptr, IGamePool * pool = nullptr)
		: IGameIterator<T>(elem), m_pool(pool)
	{
		//find the current pointer to a struct
		m_cur = (int)(
			Memory::Handle(elem).as<std::uintptr_t>() - m_pool->getData().as<std::uintptr_t>()
		) / (int)m_pool->getItemSize();
	}

	//get id of the item in the pool
	int getId() {
		return m_cur;
	}
};






//Generic pools interface(peds, objects, pickups, ...)
class IGameGenericPool
	: public Memory::IDynStructure<IGameGenericPool>, public IGamePool
{
public:
	enum FIELD {
		pData,
		bitMap,
		maxCount,
		itemSize,
		unkItemIndex,
		freeSlotIndex,
		flags
	};

	static void init() {
		struct STRUCT
		{
			void* m_pData;
			uint8_t* m_bitMap;
			int32_t m_count;
			int32_t m_itemSize;
			int32_t m_unkItemIndex;
			int32_t m_freeSlotIndex;
			uint32_t m_flags;
		};

		setFieldOffset(pData, offsetof(STRUCT, m_pData));
		setFieldOffset(bitMap, offsetof(STRUCT, m_bitMap));
		setFieldOffset(maxCount, offsetof(STRUCT, m_count));
		setFieldOffset(itemSize, offsetof(STRUCT, m_itemSize));
		setFieldOffset(unkItemIndex, offsetof(STRUCT, m_unkItemIndex));
		setFieldOffset(freeSlotIndex, offsetof(STRUCT, m_freeSlotIndex));
		setFieldOffset(flags, offsetof(STRUCT, m_flags));
	}

	IGameGenericPool(Memory::Handle base) : IDynStructure(base) {}

	uint8_t* getBitMap() {
		return getFieldPtr<uint8_t*>(bitMap);
	}

	uint32_t getCount() {
		return 0;
	}

	uint32_t getMaxCount() {
		return getFieldValue<uint32_t>(maxCount);
	}

	uint32_t getItemSize() {
		return getFieldValue<uint32_t>(itemSize);
	}

	int32_t getFreeSlotIndex() {
		return getFieldValue<int32_t>(freeSlotIndex);
	}

	Memory::Handle getData() override
	{
		return getField(pData).dereference();
	}

	Memory::Handle getBase() override
	{
		return m_base.dereference();
	}
};


//Generic pools(peds, objects, pickups, ...)
template <typename T>
class GameGenericPool
	: public IGameGenericPool, public ISingleton<GameGenericPool<T>>
{
public:
	class iterator : public IGamePoolIterator<T>
	{
		friend class GameGenericPool<T>;
		using Pool = GameGenericPool<T>;
	public:
		iterator(T* elem = nullptr)
			: IGamePoolIterator<T>(elem, Pool::GetInstancePtr())
		{}
	private:
		inline bool isItemValid(std::size_t i) override
		{
			static uint8_t*
				bitmap = Pool::GetInstancePtr()->getBitMap();
			long long num1 = bitmap[i] & 0x80;

			GameEntityStructure entity = IGamePoolIterator<T>::getItemById(i);
			if (entity.isOccupied())
			{
				return true;
			}
			return false;
		}
	};

	GameGenericPool(Memory::Handle base)
		: IGameGenericPool(base)
	{}
	
	iterator begin() {
		return &++iterator(
			getData().sub(
				getItemSize()
			).as<T*>()
		);
	}

	iterator end() {
		return getData().add(
			getMaxCount() * getItemSize()
		).as<T*>();
	}
};


//Vehicle pool
class GameVehiclePool
	: public Memory::IDynStructure<GameVehiclePool>, public ISingleton<GameVehiclePool>, public IGamePool
{
public:
	class iterator : public IGamePoolIterator<GameVehicleStructure*>
	{
		friend class GameVehiclePool;
		using Pool = GameVehiclePool;
	public:
		iterator(GameVehicleStructure** elem = nullptr)
			: IGamePoolIterator<GameVehicleStructure*>(elem, Pool::GetInstancePtr())
		{}

		GameVehicleStructure* operator&() {
			return *(GameVehicleStructure **)this->m_elem;
		}

		GameVehicleStructure& operator*() {
			return **(GameVehicleStructure **)this->m_elem;
		}
	private:
		inline bool isItemValid(std::size_t i) override
		{
			static uint32_t*
				bitmap = Pool::GetInstancePtr()->getBitMap();
			if ((bitmap[i >> 5] >> (i & 0x1F)) & 1)
			{
				return true;
			}
			return false;
		}
	};

	enum FIELD {
		pData,
		size,
		bitMap,
		count,
		lastVehicle
	};

	static void init() {
		struct STRUCT {
			GameVehicleStructure** m_pData;
			uint32_t m_size;
			char pad0[0x24];
			uint32_t* m_bitMap;
			char pad1[0x28];
			uint32_t m_count;
			uint32_t m_lastVehicle;
		};

		setFieldOffset(pData, offsetof(STRUCT, m_pData));
		setFieldOffset(size, offsetof(STRUCT, m_size));
		setFieldOffset(bitMap, offsetof(STRUCT, m_bitMap));
		setFieldOffset(count, offsetof(STRUCT, m_count));
		setFieldOffset(lastVehicle, offsetof(STRUCT, m_lastVehicle));
	}

	GameVehiclePool(Memory::Handle base)
		: IDynStructure(base)
	{
	}
	
	uint32_t getMaxCount() {
		return getFieldValue<uint32_t>(size);
	}

	uint32_t getCount() {
		return getFieldValue<uint32_t>(count);
	}

	uint32_t getItemSize() {
		return sizeof(std::uintptr_t);
	}

	uint32_t* getBitMap() {
		return getFieldPtr<uint32_t*>(bitMap);
	}

	iterator begin() {
		return &++iterator(
			getData().sub(
				getItemSize()
			).as<GameVehicleStructure**>()
		);
	}

	iterator end() {
		return &--iterator(
			getData().add(
				getMaxCount() * sizeof(std::uintptr_t)
			).as<GameVehicleStructure**>()
		);
	}

	Memory::Handle getData() override
	{
		return getField(pData).dereference();
	}

	Memory::Handle getBase() override
	{
		return m_base.dereference().dereference();
	}
};






//Class manager
class GamePool : public IGameStaticHooked
{
public:
	using Entity_t = GameGenericPool<GameEntityStructure>;
	using Ped_t = GameGenericPool<GamePedStructure>;
	using Object_t = GameGenericPool<GameObjectStructure>;
	using Pickup_t = GameGenericPool<GamePickupStructure>;
	using Vehicle_t = GameVehiclePool;

	//Entities
	static Entity_t& Entity() {
		return *Entity_t::GetInstancePtr();
	}

	//Peds
	static Ped_t& Ped() {
		return *Ped_t::GetInstancePtr();
	}

	//Objects
	static Object_t& Object() {
		return *Object_t::GetInstancePtr();
	}

	//Pickups
	static Pickup_t& Pickup() {
		return *Pickup_t::GetInstancePtr();
	}

	//Vehicles
	static Vehicle_t& Vehicle() {
		return *Vehicle_t::GetInstancePtr();
	}
};


class GamePoolHook_Gen : public IGameHook, public ISingleton<GamePoolHook_Gen>
{
public:
	void Install()
	{
		//Entities
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("4C 8B 05 ? ? ? ? 49 2B 00"),
				&genPool<GameEntityStructure>
			)
		);

		//Peds
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("48 8B 05 ? ? ? ? 48 63 50 10"),
				&genPool<GamePedStructure>
			)
		);

		//Objects
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("4C 8B 15 ? ? ? ? 85 ED"),
				&genPool<GameObjectStructure>
			)
		);

		//Pickups
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("4C 8B 05 ? ? ? ? 41 8B 58 20"),
				&genPool<GamePickupStructure>
			)
		);

		//Vehicles
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("4C 8B 3D ? ? ? ? 4D 8B 0F"),
				&vehiclePool
			)
		);
	}

	template<typename T>
	static void genPool(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}
		new GameGenericPool<T>(
			pattern.getResult().add(3).rip(4)
		);
	}

	static void vehiclePool(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}
		new GameVehiclePool(
			pattern.getResult().add(3).rip(4)
		);
	}

	void Remove()
	{

	}
};