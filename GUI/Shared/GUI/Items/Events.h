#pragma once

#include "main.h"

namespace GUI
{
	namespace Events
	{
		class ISender {};
		class EventHandler;

		class EventMessage
		{
		public:
			using Type = std::shared_ptr<EventMessage>;
			EventMessage(ISender* sender, EventHandler* eventHandler, uint64_t value = 0)
				: m_sender(sender), m_eventHandler(eventHandler), m_value(value)
			{}

			~EventMessage() {
				int a = 5;
			}

			ISender* getSender() {
				return m_sender;
			}

			void changeSender(ISender* sender) {
				m_sender = sender;
			}

			EventHandler* getEventHandler() {
				return m_eventHandler;
			}

			void changeEventHandler(EventHandler* eventHandler) {
				m_eventHandler = eventHandler;
			}

			//MY TODO: remove if not used anywhere
			template<typename T>
			T getValue() {
				return (T)m_value;
			}
		private:
			ISender* m_sender;
			EventHandler* m_eventHandler;
			uint64_t m_value;
		};
		using EventInfo = EventMessage;


		class EventHandler
		{
		public:
			using CallbackType = std::function<void(EventMessage::Type&)>;
			EventHandler(CallbackType callback)
				: m_callback(callback)
			{};
			virtual ~EventHandler() {}

			virtual void callHandler(EventMessage::Type info) = 0;

			bool canBeRemovedBy(ISender* sender) {
				return m_owner == sender && m_canBeRemoved;
			}

			void setOwner(ISender* owner) {
				if (m_owner != nullptr) {
					return;
				}
				setOwnerAnyway(owner);
			}

			void setOwnerAnyway(ISender* owner) {
				m_owner = owner;
			}

			void setCanBeRemoved(bool state) {
				m_canBeRemoved = state;
			}

			CallbackType& doCallback() {
				return m_callback;
			}
		protected:
			CallbackType m_callback;
			ISender* m_owner = nullptr;
			bool m_canBeRemoved = true;
		};
		using Event = EventHandler;


		class Messager
		{
		public:
			Messager(ISender* sender, EventHandler* event)
				: m_sender(sender)
			{
				setEvent(event);
			}

			~Messager() {
				if (isEventDefined() && getEventHandler()->canBeRemovedBy(m_sender))
					delete m_eventHandler;
			}

			void callEventHandler() {
				if (isEventDefined()) {
					getEventHandler()->callHandler(EventMessage::Type(
						new EventMessage(m_sender, m_eventHandler)
					));
				}
			}

			ISender* getSender() {
				return m_sender;
			}

			EventHandler* getEventHandler() {
				return m_eventHandler;
			}

			void setEvent(EventHandler* event) {
				m_eventHandler = event;
				if (isEventDefined())
					event->setOwner(m_sender);
			}

			bool isEventDefined() {
				return m_eventHandler != nullptr;
			}
		private:
			ISender* m_sender;
			EventHandler* m_eventHandler;
		};


		class EventStd : public EventHandler
		{
		public:
			EventStd(CallbackType callback)
				: EventHandler(callback)
			{}

			void callHandler(EventInfo::Type info) override {
				m_callback(info);
			}
		};


		class EventUI : public EventHandler
		{
		public:
			EventUI(CallbackType callback)
				: EventHandler(callback)
			{}
			~EventUI() {}

			void callHandler(EventInfo::Type info) override {
				m_eventMessages.push_back(info);
			}

			static void handleEvents() {
				for (auto &message : m_eventMessages) {
					EventHandler* eventHandler = message->getEventHandler();
					if (eventHandler == nullptr)
						continue;
					eventHandler->doCallback()(message);
				}
				m_eventMessages.clear();
			}
		private:
			inline static std::list<EventInfo::Type> m_eventMessages;
		};


		class EventHook : public ISender, public EventHandler
		{
		public:
			EventHook(EventHandler* eventHandler, void* userDataPtr)
				: m_eventHandler(eventHandler), EventHandler(nullptr), m_userDataPtr(userDataPtr)
			{}

			EventHook(void* userDataPtr)
				: EventHook(nullptr, userDataPtr)
			{}

			void callHandler(EventMessage::Type message) override {
				message->changeSender(this);
				message->changeEventHandler(m_eventHandler);
				m_eventHandler->callHandler(message);
			}

			void* getUserDataPtr() {
				return m_userDataPtr;
			}

			void setEventHandler(EventHandler* eventHandler) {
				m_eventHandler = eventHandler;
			}
		private:
			EventHandler* m_eventHandler;
			void* m_userDataPtr;
		};


		class EventSDK : public Event
		{
		public:
			EventSDK(CallbackType callback)
				: Event(callback)
			{}
			~EventSDK() {}

			void callHandler(EventInfo::Type info) override {
				m_eventMessages.push_back(info);
			}

			static void handleEvents() {
				for (auto& message : m_eventMessages) {
					auto event = message->getEventHandler();
					if (event == nullptr)
						continue;
					event->doCallback()(message);
				}
				m_eventMessages.clear();
			}
		private:
			inline static std::list<EventInfo::Type> m_eventMessages;
		};


		template<typename T>
		class OnSpecial
		{
		public:
			OnSpecial(Event* event = nullptr)
				: m_sender((ISender*)this, event)
			{};

			Event* getSpecialEvent() {
				return m_sender.getEventHandler();
			}

			T* setSpecialEvent(Event* event) {
				m_sender.setEvent(event);
				return (T*)this;
			}

			void sendSpecialEvent() {
				m_sender.callEventHandler();
			}

		private:
			Messager m_sender;
		};


		template<typename T>
		class OnHovered
		{
		public:
			OnHovered(Event* event = nullptr)
				: m_sender((ISender*)this, event)
			{};

			Event* getHoveredEvent() {
				return m_sender.getEventHandler();
			}

			T* setHoveredEvent(Event* event) {
				m_sender.setEvent(event);
				return (T*)this;
			}

			void sendHoveredEvent() {
				if (ImGui::IsItemHovered()) {
					m_sender.callEventHandler();
				}
			}

		private:
			Messager m_sender;
		};

		template<typename T>
		class OnLeftMouseClick
		{
		public:
			OnLeftMouseClick(Event* event = nullptr)
				: m_sender((ISender*)this, event)
			{};

			Event* getLeftMouseClickEvent() {
				return m_sender.getEventHandler();
			}

			T* setLeftMouseClickEvent(Event* event) {
				m_sender.setEvent(event);
				return (T*)this;
			}

			void sendLeftMouseClickEvent() {
				if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0)) {
					m_sender.callEventHandler();
				}
			}

		private:
			Messager m_sender;
		};

		template<typename T>
		class OnRightMouseClick
		{
		public:
			OnRightMouseClick(Event* event = nullptr)
				: m_sender((ISender*)this, event)
			{};

			Event* getRightMouseClickEvent() {
				return m_sender.getEventHandler();
			}

			T* setRightMouseClickEvent(Event* event) {
				m_sender.setEvent(event);
				return (T*)this;
			}

			void sendRightMouseClickEvent() {
				if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
					m_sender.callEventHandler();
				}
			}

		private:
			Messager m_sender;
		};
		
		template<typename T>
		class OnClose
		{
		public:
			OnClose(Event* event = nullptr)
				: m_sender((ISender*)this, event)
			{};

			Event* getCloseEvent() {
				return m_sender.getEventHandler();
			}

			T* setCloseEvent(Event* event) {
				m_sender.setEvent(event);
				return (T*)this;
			}

			void sendCloseEvent() {
				m_sender.callEventHandler();
			}

		private:
			Messager m_sender;
		};
	};
};