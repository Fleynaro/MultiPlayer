#pragma once

#include "main.h"

namespace GUI
{
	namespace Events
	{
		class ISender;
		class OnSpecial;
		class EventInfo
		{
		public:
			using Type = std::shared_ptr<EventInfo>;
			EventInfo(ISender* sender, uint64_t value = 0)
				: m_sender(sender), m_value(value)
			{}

			~EventInfo() {
				int a = 5;
			}

			ISender* getSender() {
				return m_sender;
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


		class Event
		{
		public:
			using CallbackType = std::function<void(EventInfo::Type&)>;
			Event(CallbackType callback)
				: m_callback(callback)
			{};
			virtual ~Event() {}

			virtual void callHandler(EventInfo::Type info) = 0;

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


		class ISender
		{
		protected:
			ISender(Event* event) {
				setEvent(event);
			}
			~ISender() {
				if (isEventDefined() && getEvent()->canBeRemovedBy(this))
					delete m_event;
			}

			virtual void callEventHandler() {
				if (isEventDefined()) {
					getEvent()->callHandler(EventInfo::Type(
						new EventInfo(this)
					));
				}
			}
		public:
			Event* getEvent() {
				return m_event;
			}

			void setEvent(Event* event) {
				m_event = event;
				if (isEventDefined())
					event->setOwner(this);
			}

			bool isEventDefined() {
				return m_event != nullptr;
			}
		private:
			Event* m_event = nullptr;
		};


		class EventStd : public Event
		{
		public:
			EventStd(CallbackType callback)
				: Event(callback)
			{}

			void callHandler(EventInfo::Type info) override {
				m_callback(info);
			}
		};


		class EventUI : public Event
		{
		public:
			EventUI(CallbackType callback)
				: Event(callback)
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
		class OnLeftMouseClick : private ISender
		{
		public:
			OnLeftMouseClick(Event* event = nullptr)
				: ISender(event)
			{};

			Event* getLeftMouseClickEvent() {
				return getEvent();
			}

			T* setLeftMouseClickEvent(Event* event) {
				setEvent(event);
				return (T*)this;
			}

			void sendLeftMouseClickEvent() {
				if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0)) {
					callEventHandler();
				}
			}
		};

		template<typename T>
		class OnRightMouseClick : private ISender
		{
		public:
			OnRightMouseClick(Event* event = nullptr)
				: ISender(event)
			{};

			Event* getRightMouseClickEvent() {
				return getEvent();
			}

			T* setRightMouseClickEvent(Event* event) {
				setEvent(event);
				return (T*)this;
			}

			void sendRightMouseClickEvent() {
				if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
					callEventHandler();
				}
			}
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