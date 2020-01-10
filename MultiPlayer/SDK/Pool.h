#pragma once


#include "NativeCaller.h"
#include "Game/GamePool.h"

#include "World/Ped/Ped.h"
#include "World/Vehicle/Vehicle.h"

namespace SDK {
	template<typename T>
	class Iterator
	{
	public:
		virtual T next() = 0;
		virtual bool hasNext() = 0;
	};

	namespace Pool
	{
		template<typename C, typename T, typename Pool>
		class Entity
			: public Iterator<T>, public Class::IExportable<C>
		{
		public:
			//for export
			C* getPersistent() override {
				return new C(m_iterator);
			}

			static C* constructor() {
				return new C;
			}
			
			Entity()
				: Entity(Pool::GetInstancePtr()->begin())
			{}

			Entity(class Pool::iterator it)
				: m_iterator(it)
			{}

			T getObj(class Pool::iterator it) {
				return SDK::Entity::GetIdByAddress((std::uintptr_t)&it);
			}

			T next() override {
				auto obj = getObj(m_iterator);
				++m_iterator;
				return obj;
			}

			bool hasNext() override {
				return m_iterator != Pool::GetInstancePtr()->end();
			}
		protected:
			class Pool::iterator m_iterator;
		};

		class Ped
			: public Entity<Pool::Ped, SE::Ped, GamePool::Ped_t>
		{
		public:
			Ped() = default;

			Ped(GamePool::Ped_t::iterator it)
				: Entity(it)
			{}
		};

		class Vehicle
			: public Entity<Pool::Vehicle, SE::Vehicle, GamePool::Vehicle_t>
		{
		public:
			Vehicle() = default;

			Vehicle(GamePool::Vehicle_t::iterator it)
				: Entity(it)
			{}
		};

		/*class Object
			: public Entity<Pool::Object, SDK::Object, GamePool::Object_t>
		{
		public:
			Object(IteratorStart start)
				: Entity(start)
			{}

			Object(GamePool::Object_t::iterator it)
				: Entity(it)
			{}
		};*/
	};
};