#pragma once
#include "main.h"
#include <bitset>

//All callback messages
enum GameEventMessageId
{
	GAME_UPDATE,
	GAME_INIT,
	GAME_INPUT,
	GAME_D3D_PRESENT,
	GAME_D3D_INIT,
	GAME_SCRIPT_EXECUTE,

	CONTEXT_UPDATER,

	count
};

//Callback message interface
class IGameEventMessage
{
public:
	using Type = std::shared_ptr<IGameEventMessage>;
	IGameEventMessage(GameEventMessageId message)
		: m_message(message)
	{}

	GameEventMessageId getMessageId() {
		return m_message;
	}
private:
	GameEventMessageId m_message;
};

//Game event message handler and filter interface
class IGameEventHandler
{
public:
	enum class Priority {
		VERY_LOW,
		LOW,
		NORMAL,
		HIGH,
		VERY_HIGH
	};

	IGameEventHandler() = default;

	//filter
	virtual void callback(IGameEventMessage::Type &message, bool& result, bool& doContinue) = 0;
	virtual bool filter(IGameEventMessage::Type &message) = 0;

	void setPriority(Priority priority) {
		m_priority = priority;
	}

	Priority getPriority() {
		return m_priority;
	}
private:
	Priority m_priority = Priority::NORMAL;
};


class IGameEventHandlerProxy;
//proxy message
class GameEventProxyMessage
{
public:
	GameEventProxyMessage(IGameEventHandlerProxy *proxy, IGameEventMessage::Type &message)
		: m_proxy(proxy), m_message(message)
	{}

	IGameEventHandlerProxy* getProxyHandler() {
		return m_proxy;
	}

	IGameEventMessage::Type getMessage() {
		return m_message;
	}
private:
	IGameEventMessage::Type m_message;
	IGameEventHandlerProxy* m_proxy;
};


class GameEventProxyMessageAgregator;
//Game event message handler proxy
class IGameEventHandlerProxy
{
	friend class GameEventProxyMessageAgregator;
public:
	IGameEventHandlerProxy(GameEventProxyMessageAgregator* proxyAgregator = nullptr) {
		setProxyMessageAgregator(proxyAgregator);
	};

	void setProxyMessageAgregator(GameEventProxyMessageAgregator *proxyNode) {
		m_proxyAgregator = proxyNode;
	}

	GameEventProxyMessageAgregator* getProxyMessageAgregator() {
		return m_proxyAgregator;
	}

	bool hasProxy() {
		return getProxyMessageAgregator() != nullptr;
	}
protected:
	virtual void callback_orig(IGameEventMessage::Type& message, bool& result, bool& doContinue) = 0;
private:
	GameEventProxyMessageAgregator *m_proxyAgregator = nullptr;
};


//It storages recieved messages of DIFFERENT type.
//Should call <sendMessages> which calls a special handler for each message.
class GameEventProxyMessageAgregator
{
public:
	GameEventProxyMessageAgregator() = default;
	~GameEventProxyMessageAgregator() {
		for (auto it : m_messages)
			delete it;
	}

	//save the message to handle it later
	void recieveMessage(GameEventProxyMessage* message) {
		m_messages.push_back(message);
	}

	//handle all storaged messages calling original handlers for each message(messaged of various types)
	void sendMessages() {
		for (auto& it : m_messages) {
			if (it == nullptr)
				continue;

			bool result;
			bool doContinue;
			sendMessage(it, result, doContinue);

			if (!doContinue) {
				//removeMessagesByType(it->getMessage()->getMessageId());
			}

			delete it;
			it = nullptr;
		}
		m_messages.clear();
	}

	void removeMessagesByType(GameEventMessageId id) {
		for (auto& it : m_messages) {
			if (it == nullptr)
				continue;

			if (it->getMessage()->getMessageId() == id) {
				delete it;
				it = nullptr;
			}
		}
	}

	void clear() {
		m_messages.clear();
	}
private:
	//messages have to be handled later
	std::list<GameEventProxyMessage*> m_messages;

	virtual void sendMessage(GameEventProxyMessage* it, bool& result, bool& doContinue) {
		auto mes = it->getMessage();
		it->getProxyHandler()->callback_orig(
			mes, result, doContinue
		);
	}
};


template<typename T = IGameEventHandler>
class GameEventProxyHandler : public T, public IGameEventHandlerProxy
{
public:
	//message interception from an ordinary handler(it is T)
	void callback(IGameEventMessage::Type &message, bool& result, bool& doContinue) override {
		if (!T::filter(message))
			return;
		sendMessage(message);
	}

private:
	//call the original handler
	void callback_orig(IGameEventMessage::Type &message, bool& result, bool& doContinue) override {
		T::callback(message, result, doContinue);
	}

	//save the message to handle it later
	void sendMessage(IGameEventMessage::Type &message) {
		if (!hasProxy())
			return;
		getProxyMessageAgregator()->recieveMessage(
			new GameEventProxyMessage(this, message)
		);
	}
};




//Game event message sender
class IGameEventGenPublisher
{
public:
	static void addEventHandler(IGameEventHandler *handler)
	{
		for (auto it = m_eventHandlers.rbegin(); it != m_eventHandlers.rend(); it++) {
			if (handler->getPriority() <= (*it)->getPriority()) {
				m_eventHandlers.insert(it.base(), handler);
				return;
			}
		}
		m_eventHandlers.push_front(handler);
	}

	static void removeEventHandler(IGameEventHandler *handler)
	{
		m_eventHandlers.remove(handler);
	}

	static bool sendEventToAll(IGameEventMessage::Type &message)
	{
		for (auto handler : m_eventHandlers) {
			bool doContinue = true;
			bool result = true;
			handler->callback(message, result, doContinue);
			if (!doContinue) {
				return result;
			}
		}
		return true;
	}
private:
	inline static std::list<IGameEventHandler*> m_eventHandlers;
};

//Concrete template sender
template<typename T>
class IGameEventPublisher
{
public:
	static void addEventHandler(T* handler)
	{
		IGameEventGenPublisher::addEventHandler(handler);
	}

	static void removeEventHandler(T* handler)
	{
		IGameEventGenPublisher::removeEventHandler(handler);
	}

	static bool sendEventToAll(IGameEventMessage::Type message)
	{
		return IGameEventGenPublisher::sendEventToAll(message);
	}
};



