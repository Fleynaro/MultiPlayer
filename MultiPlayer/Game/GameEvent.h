#pragma once



#include "main.h"
#include <bitset>
#include "Game/GameException.h"

//need to stop next executing of the game event
class GameEventException : public IGameException
{
public:
	GameEventException(bool result)
		: IGameException(""), m_result(result)
	{};

	bool m_result;
};

//All callback messages
enum GameEventMessage
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
	IGameEventMessage(GameEventMessage message)
		: m_message(message)
	{}

	GameEventMessage getMessage() {
		return m_message;
	}
private:
	GameEventMessage m_message;
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
	virtual void callback(IGameEventMessage::Type &message) = 0;
	virtual bool filter(IGameEventMessage::Type &message) = 0;

	void breakListener(bool result = true) {
		throw GameEventException(result);
	}

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
class IGameEventMessageProxy
{
public:
	IGameEventMessageProxy(IGameEventHandlerProxy *proxy, IGameEventMessage::Type &message)
		: m_proxy(proxy), m_message(message)
	{}
	IGameEventHandlerProxy* getProxy() {
		return m_proxy;
	}

	IGameEventMessage::Type getMessage() {
		return m_message;
	}
private:
	IGameEventMessage::Type m_message;
	IGameEventHandlerProxy* m_proxy;
};


class IGameEventHandlerProxyNode;
//Game event message handler proxy
class IGameEventHandlerProxy
{
public:
	IGameEventHandlerProxy(IGameEventHandlerProxyNode* proxyNode = nullptr) {
		setProxyNode(proxyNode);
	};

	void setProxyNode(IGameEventHandlerProxyNode *proxyNode) {
		m_proxyNode = proxyNode;
	}

	bool hasProxy() {
		return m_proxyNode != nullptr;
	}

	IGameEventHandlerProxyNode* getProxy() {
		return m_proxyNode;
	}

	virtual void callback_orig(IGameEventMessage::Type &message) = 0;
protected:
	IGameEventHandlerProxyNode *m_proxyNode = nullptr;
};


//Game event message handler proxy node the messages should be sent through
class IGameEventHandlerProxyNode
{
public:
	void recieveMessage(IGameEventMessageProxy* message) {
		m_messages.push_back(message);
	}
protected:
	IGameEventHandlerProxyNode() = default;
	~IGameEventHandlerProxyNode() {
		for (auto it : m_messages)
			delete it;
	}

	void sendMessages() {
		for (auto it : m_messages) {
			sendMessage(it);
			delete it;
		}
		m_messages.clear();
	}

	virtual void sendMessage(IGameEventMessageProxy* it) {
		auto mes = it->getMessage();
		it->getProxy()->callback_orig(
			mes
		);
	}
protected:
	std::list<IGameEventMessageProxy*> m_messages;
};


template<typename T = IGameEventHandler>
class GameEventHandlerProxy : public T, public IGameEventHandlerProxy
{
public:
	using IGameEventHandlerProxy::IGameEventHandlerProxy;

	void callback(IGameEventMessage::Type &message) override {
		if (!T::filter(message))
			return;
		sendMessage(message);
	}

	void callback_orig(IGameEventMessage::Type &message) override {
		T::callback(message);
	}

	void sendMessage(IGameEventMessage::Type &message) {
		if (!hasProxy())
			return;
		m_proxyNode->recieveMessage(
			new IGameEventMessageProxy(this, message)
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
		try {
			for (auto handler : m_eventHandlers) {
				handler->callback(message);
			}
		}
		catch (GameEventException ex) {
			return ex.m_result;
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



