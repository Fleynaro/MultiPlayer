#pragma once

#include "main.h"

namespace GUI
{
	namespace Events
	{
		class ISender {};
		class EventHandler;

		class IEventMessage
		{
		public:
			virtual ISender* getSender() = 0;
			virtual EventHandler* getEventHandler() = 0;
		};

		class EventMessage : public IEventMessage
		{
		public:
			using Type = std::shared_ptr<IEventMessage>;
			EventMessage(ISender* sender, EventHandler* eventHandler, uint64_t value = 0)
				: m_sender(sender), m_eventHandler(eventHandler), m_value(value)
			{}

			~EventMessage() {
				int a = 5;
			}

			ISender* getSender() override {
				return m_sender;
			}

			EventHandler* getEventHandler() override {
				return m_eventHandler;
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

			template<typename T>
			void callEventHandler(T value) {
				callEventHandler((uint64_t&)value);
			}

			void callEventHandler(uint64_t value = 0) {
				callEventHandler(EventMessage::Type(
					new EventMessage(m_sender, m_eventHandler, value)
				));
			}

			void callEventHandler(EventMessage::Type eventMessage) {
				if (isEventDefined()) {
					getEventHandler()->callHandler(eventMessage);
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

		class EventHook;
		class EventHookedMessage : public IEventMessage
		{
		public:
			EventHookedMessage(EventHook* newSender, EventMessage::Type& message)
				: m_newSender(newSender), m_message(message)
			{}

			ISender* getSender() override;

			EventHandler* getEventHandler() override;

			void* getUserDataPtr();

			ISender* getRealSender() {
				return m_message->getSender();
			}

			EventMessage::Type& getMessage() {
				return m_message;
			}
		private:
			EventHook* m_newSender;
			EventMessage::Type m_message;
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
				m_eventHandler->callHandler(EventMessage::Type(
					new EventHookedMessage(this, message)
				));
			}

			void* getUserDataPtr() {
				return m_userDataPtr;
			}

			void setEventHandler(EventHandler* eventHandler) {
				m_eventHandler = eventHandler;
			}

			EventHandler* getEventHandler() {
				return m_eventHandler;
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
				onSpecial();
			}

			virtual void onSpecial() {
				m_sender.callEventHandler();
			}
		private:
			Messager m_sender;
		};

		enum HoverType
		{
			HoveredIn,
			HoveredOut,
			HoveredUpdate
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

			virtual bool isHovered() {
				return ImGui::IsItemHovered();
			}

			void sendHoveredEvent() {
				if (isHovered()) {
					onHoveredUpdate();
					if (!m_isHoveredIn) {
						onHoveredIn();
						m_isHoveredIn = true;
					}
				}
				else {
					if (m_isHoveredIn) {
						onHoveredOut();
						m_isHoveredIn = false;
					}
				}
			}

			virtual void onHoveredUpdate() {
				m_sender.callEventHandler(HoveredUpdate);
			}

			virtual void onHoveredIn() {
				m_sender.callEventHandler(HoveredIn);
			}

			virtual void onHoveredOut() {
				m_sender.callEventHandler(HoveredOut);
			}
		private:
			Messager m_sender;
			bool m_isHoveredIn = false;
		};

		enum FocusType
		{
			FocusedIn,
			FocusedOut,
			FocusedUpdate
		};

		template<typename T>
		class OnFocused
		{
		public:
			OnFocused(Event* event = nullptr)
				: m_sender((ISender*)this, event)
			{};

			Event* getFocusedEvent() {
				return m_sender.getEventHandler();
			}

			T* setFocusedEvent(Event* event) {
				m_sender.setEvent(event);
				return (T*)this;
			}

			virtual bool isFocused() {
				return ImGui::IsItemFocused();
			}

			void sendFocusedEvent() {
				if (isFocused()) {
					onFocusedUpdate();
					if (!m_isFocusedIn) {
						onFocusedIn();
						m_isFocusedIn = true;
					}
				}
				else {
					if (m_isFocusedIn) {
						onFocusedOut();
						m_isFocusedIn = false;
					}
				}
			}

			virtual void onFocusedUpdate() {
				m_sender.callEventHandler(FocusedUpdate);
			}

			virtual void onFocusedIn() {
				m_sender.callEventHandler(FocusedIn);
			}

			virtual void onFocusedOut() {
				m_sender.callEventHandler(FocusedOut);
			}
		private:
			Messager m_sender;
			bool m_isFocusedIn = false;
		};

		enum VisibleType
		{
			VisibleOn,
			VisibleOff,
			VisibleUpdate
		};

		template<typename T>
		class OnVisible
		{
		public:
			OnVisible(Event* event = nullptr)
				: m_sender((ISender*)this, event)
			{};

			Event* getVisibleEvent() {
				return m_sender.getEventHandler();
			}

			T* setVisibleEvent(Event* event) {
				m_sender.setEvent(event);
				return (T*)this;
			}

			virtual bool isVisible() {
				return ImGui::IsItemVisible();
			}

			void sendVisibleEvent() {
				if (isVisible()) {
					onVisibleUpdate();
					if (!m_isVisible) {
						onVisibleOn();
						m_isVisible = true;
					}
				}
				else {
					if (m_isVisible) {
						onVisibleOff();
						m_isVisible = false;
					}
				}
			}

			virtual void onVisibleUpdate() {
				m_sender.callEventHandler(VisibleUpdate);
			}

			virtual void onVisibleOn() {
				m_sender.callEventHandler(VisibleOn);
			}

			virtual void onVisibleOff() {
				m_sender.callEventHandler(VisibleOff);
			}
		private:
			Messager m_sender;
			bool m_isVisible = false;
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
					onLeftMouseClick();
				}
			}

			virtual void onLeftMouseClick() {
				m_sender.callEventHandler();
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
					onRightMouseClick();
				}
			}

			virtual void onRightMouseClick() {
				m_sender.callEventHandler();
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
				onClose();
			}

			virtual void onClose() {
				m_sender.callEventHandler();
			}
		private:
			Messager m_sender;
		};
	};
};