#pragma once

#include "main.h"

namespace GUI
{
	namespace Events
	{
		class ISender;
		class OnSpecial;
		class EventMessage
		{
		public:
			using Type = std::shared_ptr<EventMessage>;
			EventMessage(ISender* sender, uint64_t value = 0)
				: m_sender(sender), m_value(value)
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

			OnSpecial* getOwner() {
				return (OnSpecial*)getSender();
			}

			template<typename T>
			T getValue() {
				return (T)m_value;
			}
		private:
			ISender* m_sender;
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


		//MY TODO: rename to Sender
		class ISender
		{
		protected:
			ISender(EventHandler* event) {
				setEvent(event);
			}
			~ISender() {
				if (isEventDefined() && getEvent()->canBeRemovedBy(this))
					delete m_event;
			}

			virtual void callEventHandler() {
				if (isEventDefined()) {
					getEvent()->callHandler(EventMessage::Type(
						new EventMessage(this)
					));
				}
			}
		public:
			EventHandler* getEvent() {
				return m_event;
			}

			void setEvent(EventHandler* event) {
				m_event = event;
				if (isEventDefined())
					event->setOwner(this);
			}

			bool isEventDefined() {
				return m_event != nullptr;
			}
		private:
			EventHandler* m_event = nullptr;
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
					auto event = message->getSender()->getEvent();
					if (event == nullptr)
						continue;
					event->doCallback()(message);
				}
				m_eventMessages.clear();
			}
		private:
			inline static std::list<EventInfo::Type> m_eventMessages;
		};


		class EventHook : public ISender, public EventHandler
		{
		public:
			EventHook(Event* event, void* userDataPtr)
				: ISender(event), EventHandler(nullptr), m_userDataPtr(userDataPtr)
			{}

			void callHandler(EventInfo::Type info) override {
				info->changeSender(this);
				getEvent()->callHandler(info);
			}

			void* getUserDataPtr() {
				return m_userDataPtr;
			}
		private:
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
					auto event = message->getSender()->getEvent();
					if (event == nullptr)
						continue;
					event->doCallback()(message);
				}
				m_eventMessages.clear();
			}
		private:
			inline static std::list<EventInfo::Type> m_eventMessages;
		};


		class OnSpecial : private ISender
		{
		public:
			OnSpecial(Event* event = nullptr)
				: ISender(event)
			{};

			Event* getSpecialEvent() {
				return getEvent();
			}

			void sendSpecialEvent() {
				callEventHandler();
			}
		};


		template<typename T>
		class OnHovered : private ISender
		{
		public:
			OnHovered(Event* event = nullptr)
				: ISender(event)
			{};

			Event* getHoveredEvent() {
				return getEvent();
			}

			T* setHoveredEvent(Event* event) {
				setEvent(event);
				return (T*)this;
			}

			void sendHoveredEvent() {
				if (ImGui::IsItemHovered()) {
					callEventHandler();
				}
			}
		};

		template<typename T>
		class OnLeftMouseClick
		{
		public:
			OnLeftMouseClick(ISender* sender)
				: m_sender(sender)
			{};

			Event* getLeftMouseClickEvent() {
				return m_sender->getEvent();
			}

			T* setLeftMouseClickEvent(Event* event) {
				m_sender->setEvent(event);
				return (T*)this;
			}

			void sendLeftMouseClickEvent() {
				if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0)) {
					m_sender->callEventHandler();
				}
			}

		private:
			ISender* m_sender;
		};

		template<typename T>
		class OnRightMouseClick
		{
		public:
			OnRightMouseClick(ISender* sender)
				: m_sender(sender)
			{};

			Event* getRightMouseClickEvent() {
				return m_sender->getEvent();
			}

			T* setRightMouseClickEvent(Event* event) {
				m_sender->setEvent(event);
				return (T*)this;
			}

			void sendRightMouseClickEvent() {
				if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
					m_sender->callEventHandler();
				}
			}

		private:
			ISender* m_sender;
		};
		
		template<typename T>
		class OnClose : private ISender
		{
		public:
			OnClose(Event* event = nullptr)
				: ISender(event)
			{};

			Event* getCloseEvent() {
				return getEvent();
			}

			T* setCloseEvent(Event* event) {
				setEvent(event);
				return (T*)this;
			}

			void sendCloseEvent() {
				callEventHandler();
			}
		};
	};
};