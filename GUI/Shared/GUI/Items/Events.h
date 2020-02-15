#pragma once

#include "main.h"

namespace GUI
{
	namespace Events
	{
		class ISender
		{
		public:
			virtual bool isGuiItem() {
				return true;
			}
		};
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


		//MYTODO: 1) rename to Event
		class Messager
		{
		public:
			Messager(ISender* sender, EventHandler* eventHandler = nullptr)
				: m_sender(sender)
			{
				if(eventHandler != nullptr)
					*this += eventHandler;
			}

			~Messager() {
				for (auto handler : m_eventHandlers) {
					if (handler->canBeRemovedBy(m_sender)) {
						delete handler;
					}
				}
			}

			template<typename T>
			void callEventHandler(T value) {
				callEventHandler((uint64_t&)value);
			}

			void callEventHandler(uint64_t value = 0) {
				for (auto handler : getEventHandlers()) {
					handler->callHandler(EventMessage::Type(
						new EventMessage(m_sender, handler, value)
					));
				}
			}

			std::list<EventHandler*>& getEventHandlers() {
				return m_eventHandlers;
			}

			ISender* getSender() {
				return m_sender;
			}

			Messager& operator+=(EventHandler* eventHandler) {
				eventHandler->setOwner(m_sender);
				m_eventHandlers.push_back(eventHandler);
				return *this;
			}

			Messager& operator-=(EventHandler* eventHandler) {
				m_eventHandlers.remove(eventHandler);
				return *this;
			}
		private:
			ISender* m_sender; //from
			std::list<EventHandler*> m_eventHandlers; //to
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

			void callHandler(EventMessage::Type message) override;

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
			EventHookedMessage(EventHook* newSender, EventMessage::Type message)
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
				if (m_eventHandler == nullptr)
					return;
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
			OnSpecial(ISender* sender, Event* event = nullptr)
				: m_messager(sender, event)
			{};

			Messager& getSpecialEvent() {
				return m_messager;
			}

			void sendSpecialEvent() {
				onSpecial();
			}

			virtual void onSpecial() {
				m_messager.callEventHandler();
			}
		private:
			Messager m_messager;
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
			OnHovered(ISender* sender, Event* event = nullptr)
				: m_messager(sender, event)
			{};

			Messager& getHoveredEvent() {
				return m_messager;
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
				m_messager.callEventHandler(HoveredUpdate);
			}

			virtual void onHoveredIn() {
				m_messager.callEventHandler(HoveredIn);
			}

			virtual void onHoveredOut() {
				m_messager.callEventHandler(HoveredOut);
			}
		private:
			Messager m_messager;
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
			OnFocused(ISender* sender, Event* event = nullptr)
				: m_messager(sender, event)
			{};

			Messager& getFocusedEvent() {
				return m_messager;
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
				m_messager.callEventHandler(FocusedUpdate);
			}

			virtual void onFocusedIn() {
				m_messager.callEventHandler(FocusedIn);
			}

			virtual void onFocusedOut() {
				m_messager.callEventHandler(FocusedOut);
			}
		private:
			Messager m_messager;
		protected:
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
			OnVisible(ISender* sender, Event* event = nullptr)
				: m_messager(sender, event)
			{};

			Messager& getVisibleEvent() {
				return m_messager;
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
				m_messager.callEventHandler(VisibleUpdate);
			}

			virtual void onVisibleOn() {
				m_messager.callEventHandler(VisibleOn);
			}

			virtual void onVisibleOff() {
				m_messager.callEventHandler(VisibleOff);
			}
		private:
			Messager m_messager;
			bool m_isVisible = false;
		};

		template<typename T>
		class OnLeftMouseClick
		{
		public:
			OnLeftMouseClick(ISender* sender, Event* event = nullptr)
				: m_messager(sender, event)
			{};

			Messager& getLeftMouseClickEvent() {
				return m_messager;
			}

			void sendLeftMouseClickEvent() {
				if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0)) {
					onLeftMouseClick();
				}
			}

			virtual void onLeftMouseClick() {
				m_messager.callEventHandler();
			}
		private:
			Messager m_messager;
		};

		template<typename T>
		class OnRightMouseClick
		{
		public:
			OnRightMouseClick(ISender* sender, Event* event = nullptr)
				: m_messager(sender, event)
			{};

			Messager& getRightMouseClickEvent() {
				return m_messager;
			}

			void sendRightMouseClickEvent() {
				if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
					onRightMouseClick();
				}
			}

			virtual void onRightMouseClick() {
				m_messager.callEventHandler();
			}
		private:
			Messager m_messager;
		};
		
		template<typename T>
		class OnClose
		{
		public:
			OnClose(ISender* sender, Event* event = nullptr)
				: m_messager(sender, event)
			{};

			Messager& getCloseEvent() {
				return m_messager;
			}

			void sendCloseEvent() {
				onClose();
			}

			virtual void onClose() {
				m_messager.callEventHandler();
			}
		private:
			Messager m_messager;
		};
	};
};