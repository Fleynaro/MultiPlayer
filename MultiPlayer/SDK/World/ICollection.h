#pragma once


#include "Ped/Ped.h"


namespace SDK {
	template<typename Key, typename Value>
	class IEntityCollection
	{
	public:
		using Storage = std::map<Key, Value*>;
		IEntityCollection(Entity* owner)
			: m_owner(owner)
		{}
		~IEntityCollection() {
			for (auto it : m_items) {
				delete it.second;
			}
		}

		///<summary></summary>
		Value* operator [](Key key) {
			return getItem(key);
		}

		///<summary></summary>
		Value* findItem(Key key) {
			auto it = m_items.find(key);
			if (it != m_items.end())
			{
				return it->second;
			}
			return nullptr;
		}

		///<summary></summary>
		Value* getItem(Key key) {
			Value* item = findItem(key);
			if (item == nullptr) {
				if (!hasItem(key)) {
					return nullptr;
				}

				auto item = createItem(key);
				addItem(key, item);
			}
			return item;
		}

		///<summary></summary>
		void addItem(Key key, Value* item) {
			m_items.insert(
				std::make_pair(key, item)
			);
		}

		///<summary></summary>
		virtual bool hasItem(Key key) = 0;

		///<summary></summary>
		virtual Value* createItem(Key key) = 0;

		///<summary></summary>
		Entity* getOwner() {
			return m_owner;
		}
	private:
		Entity* m_owner = nullptr;
		Storage m_items;
	};


	template<typename Key, typename Value>
	class IPedCollection : public IEntityCollection<Key, Value>
	{
	public:
		IPedCollection(Ped* owner)
			: IEntityCollection<Key, Value>(owner)
		{}

		///<summary></summary>
		Ped* getOwner() {
			return (Ped*)IEntityCollection<Key, Value>::getOwner();
		}
	};
};