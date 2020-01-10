#pragma once

#include "main.h"
#include "Utility/FileWrapper.h"

namespace Cfg
{
	class Config;

	class Item
	{
		friend class Config;
	public:
		Item() = default;
		Item(Config* parent) : m_parent(parent) {}

		Config* getParent() {
			return m_parent;
		}
		
		virtual bool isConfig() = 0;
		virtual std::string print() = 0;
	private:
		Config* m_parent = nullptr;

		void setParent(Config* parent) {
			m_parent = parent;
		}
	};

	template<typename T>
	class Value : public Item
	{
	public:
		Value(T value) : m_value(value) {}

		T& operator*() {
			return get();
		}

		T& get() {
			return m_value;
		}

		void set(T value) {
			m_value = value;
		}

		std::string print() override {
			if constexpr (std::is_same<T, int>::value) {
				return "int value = " + std::to_string((int)get()) + "\n";
			}
			else if constexpr (std::is_same<T, float>::value) {
				return "float value = " + std::to_string((float)get()) + "\n";
			}
			else if constexpr (std::is_same<T, double>::value) {
				return "double value = " + std::to_string((double)get()) + "\n";
			}
			else if constexpr (std::is_same<T, std::string>::value) {
				return "str value = " + (std::string)get() + "\n";
			}
			return "type not supported to print\n";
		}

		bool isConfig() override {
			return false;
		}
	private:
		T m_value;
	};

	//config file; it can store other configs and values
	class Config : public Item
	{
	public:
		Config() = default;
		Config(Config* parent) : Item(parent) {};
		~Config() {
			auto items = getItems();
			for (auto it : items) {
				delete it;
			}
		}

		Config& operator [](std::string key) {
			return getConfig(key);
		}

		template<typename T>
		Value<T>& getValue(std::string key) {
			return *(Value<T>*)m_items[key];
		}
		
		Config& getConfig(std::string key) {
			return *(Config*)m_items[key];
		}

		template<typename T>
		Config& setValue(std::string key, Value<T>* value) {
			if (m_readOnly)
				return *this;
			m_items[key] = value;
			value->setParent(this);
			return *this;
		}

		Config& beginConfig(std::string key) {
			if (m_readOnly)
				return *this;
			auto cfg = new Config(this);
			m_items[key] = cfg;
			return *cfg;
		}

		Config& endConfig() {
			return *getParent();
		}

		std::list<Item*> getItems() {
			std::list<Item*> items;
			for (auto it : m_items) {
				items.push_back(it.second);
			}
			return items;
		}
		
		std::string print() override {
			std::string msg = "config[\n";
			auto items = getItems();
			for (auto it : items) {
				msg += it->print();
			}
			return msg + "]\n";
		}

		bool isConfig() override {
			return true;
		}
	private:
		std::map<std::string, Item*> m_items;
		bool m_readOnly = false;
	};

	//if config inited by external data
	class IExternalInit
	{
	public:
		IExternalInit() = default;
		virtual void defaultInit() = 0;
	};

	//if config inited by json data
	class IJsonInit : public IExternalInit
	{
	public:
		IJsonInit() = default;
		virtual void initByJson(json& j) = 0;
	};
};