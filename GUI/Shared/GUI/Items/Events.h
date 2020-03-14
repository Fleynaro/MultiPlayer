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

		template<typename ...ArgsType>
		class EventHandler;

		class IEventMessage
		{
		public:
			virtual ISender* getSender() = 0;
			virtual void execute() = 0;
		};

		class IEventMessageReceiver
		{
		public:
			virtual void addEventMessage(IEventMessage* message) = 0;
			virtual void handleEventMessages() = 0;
		};

		template<typename ...ArgsType>
		class EventHandler
		{
		public:
			using CallbackType = std::function<void(ArgsType...)>;

			EventHandler(CallbackType callback)
				: m_callback(callback)
			{};

			~EventHandler() {}

			void invoke(std::tuple<ArgsType...> args) {
				std::apply(m_callback, args);
			}

			void invoke(ArgsType... args) {
				m_callback(args...);
			}

			bool canBeRemovedBy(ISender* sender) {
				return m_owner == sender && m_canBeRemoved;
			}

			void setOwner(ISender* owner) {
				if (m_owner != nullptr) {
					return;
				}
				setOwnerAnyway(owner);
			}

			ISender* getSender() {
				return m_owner;
			}

			void setOwnerAnyway(ISender* owner) {
				m_owner = owner;
			}

			void setCanBeRemoved(bool state) {
				m_canBeRemoved = state;
			}
		protected:
			CallbackType m_callback;
			ISender* m_owner = nullptr;
			bool m_canBeRemoved = true;
		};

		template<typename ...ArgsType>
		class EventMessage : public IEventMessage
		{
		public:
			using EventHandlerType = EventHandler<ArgsType...>;

			EventMessage(EventHandlerType* eventHandler, std::tuple<ArgsType...> arguments)
				: m_eventHandler(eventHandler), m_arguments(arguments)
			{}

			~EventMessage() {}

			ISender* getSender() override {
				return m_eventHandler->getSender();
			}

			void execute() override {
				m_eventHandler->invoke(m_arguments);
			}
		private:
			EventHandlerType* m_eventHandler;
			std::tuple<ArgsType...> m_arguments;
		};

		template<typename ...ArgsType>
		[[nodiscard]]
		static EventHandler<ArgsType...>* Listener(const std::function<void(ArgsType...)>& callback) {
			return new EventHandler<ArgsType...>(callback);
		}

		//MYTODO: 1) rename to Event
		template<typename ...ArgsType>
		class Event
		{
		public:
			using EventHandlerType = EventHandler<ArgsType...>;

			Event(ISender* sender, IEventMessageReceiver* receiver)
				: m_sender(sender), m_receiver(receiver)
			{}

			Event(ISender* sender, IEventMessageReceiver* receiver, EventHandlerType* eventHandler)
				: Event(sender, receiver)
			{
				*this += eventHandler;
			}

			~Event() {
				for (auto handler : m_eventHandlers) {
					if (handler->canBeRemovedBy(m_sender)) {
						delete handler;
					}
				}
			}

			void invoke(ArgsType... args) {
				for (auto handler : getEventHandlers()) {
					m_receiver->addEventMessage(new EventMessage<ArgsType...>(handler, std::make_tuple(args...)));
				}
			}

			std::list<EventHandlerType*>& getEventHandlers() {
				return m_eventHandlers;
			}

			ISender* getSender() {
				return m_sender;
			}

			Event& operator+=(std::function<void(ArgsType...)> callback) {
				return (*this += Listener(callback));
			}

			Event& operator+=(EventHandlerType* eventHandler) {
				if (eventHandler != nullptr) {
					eventHandler->setOwner(m_sender);
					m_eventHandlers.push_front(eventHandler);
				}
				return *this;
			}

			Event& operator-=(EventHandlerType* eventHandler) {
				if (eventHandler != nullptr) {
					m_eventHandlers.remove(eventHandler);
				}
				return *this;
			}
		private:
			ISender* m_sender;
			IEventMessageReceiver* m_receiver;
			std::list<EventHandlerType*> m_eventHandlers;
		};


		using SpecialEventType = Event<ISender*>;
		template<typename T>
		class OnSpecial
		{
		public:
			OnSpecial(ISender* sender, IEventMessageReceiver* receiver, SpecialEventType::EventHandlerType* eventHandler = nullptr)
				: m_messager(sender, receiver, eventHandler)
			{};

			auto& getSpecialEvent() {
				return m_messager;
			}

			void sendSpecialEvent() {
				onSpecial();
			}

			virtual void onSpecial() {
				m_messager.invoke(m_messager.getSender());
			}
		private:
			SpecialEventType m_messager;
		};

		enum HoverType
		{
			HoveredIn,
			HoveredOut,
			HoveredUpdate
		};

		using HoveredEventType = Event<ISender*, HoverType>;
		template<typename T>
		class OnHovered
		{
		public:
			OnHovered(ISender* sender, IEventMessageReceiver* receiver, HoveredEventType::EventHandlerType* eventHandler = nullptr)
				: m_messager(sender, receiver, eventHandler)
			{};

			auto& getHoveredEvent() {
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
				m_messager.invoke(m_messager.getSender(), HoveredUpdate);
			}

			virtual void onHoveredIn() {
				m_messager.invoke(m_messager.getSender(), HoveredIn);
			}

			virtual void onHoveredOut() {
				m_messager.invoke(m_messager.getSender(), HoveredOut);
			}
		private:
			HoveredEventType m_messager;
			bool m_isHoveredIn = false;
		};

		enum FocusType
		{
			FocusedIn,
			FocusedOut,
			FocusedUpdate
		};

		using FocusedEventType = Event<ISender*, FocusType>;
		template<typename T>
		class OnFocused
		{
		public:
			OnFocused(ISender* sender, IEventMessageReceiver* receiver, FocusedEventType::EventHandlerType* eventHandler = nullptr)
				: m_messager(sender, receiver, eventHandler)
			{};

			auto& getFocusedEvent() {
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
				m_messager.invoke(m_messager.getSender(), FocusedUpdate);
			}

			virtual void onFocusedIn() {
				m_messager.invoke(m_messager.getSender(), FocusedIn);
			}

			virtual void onFocusedOut() {
				m_messager.invoke(m_messager.getSender(), FocusedOut);
			}
		private:
			FocusedEventType m_messager;
		protected:
			bool m_isFocusedIn = false;
		};

		enum VisibleType
		{
			VisibleOn,
			VisibleOff,
			VisibleUpdate
		};

		using VisibleEventType = Event<ISender*, VisibleType>;
		template<typename T>
		class OnVisible
		{
		public:
			OnVisible(ISender* sender, IEventMessageReceiver* receiver, VisibleEventType::EventHandlerType* eventHandler = nullptr)
				: m_messager(sender, receiver, eventHandler)
			{}

			auto& getVisibleEvent() {
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
				m_messager.invoke(m_messager.getSender(), VisibleUpdate);
			}

			virtual void onVisibleOn() {
				m_messager.invoke(m_messager.getSender(), VisibleOn);
			}

			virtual void onVisibleOff() {
				m_messager.invoke(m_messager.getSender(), VisibleOff);
			}
		private:
			VisibleEventType m_messager;
			bool m_isVisible = false;
		};

		using ClickEventType = Event<ISender*>;
		template<typename T>
		class OnLeftMouseClick
		{
		public:
			OnLeftMouseClick(ISender* sender, IEventMessageReceiver* receiver, ClickEventType::EventHandlerType* eventHandler = nullptr)
				: m_messager(sender, receiver, eventHandler)
			{};

			auto& getLeftMouseClickEvent() {
				return m_messager;
			}

			void sendLeftMouseClickEvent() {
				if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0)) {
					onLeftMouseClick();
				}
			}

			virtual void onLeftMouseClick() {
				m_messager.invoke(m_messager.getSender());
			}
		private:
			ClickEventType m_messager;
		};

		using ClickEventType = Event<ISender*>;
		template<typename T>
		class OnRightMouseClick
		{
		public:
			OnRightMouseClick(ISender* sender, IEventMessageReceiver* receiver, ClickEventType::EventHandlerType* eventHandler = nullptr)
				: m_messager(sender, receiver, eventHandler)
			{};

			auto& getRightMouseClickEvent() {
				return m_messager;
			}

			void sendRightMouseClickEvent() {
				if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
					onRightMouseClick();
				}
			}

			virtual void onRightMouseClick() {
				m_messager.invoke(m_messager.getSender());
			}
		private:
			ClickEventType m_messager;
		};

		using ClickEventType = Event<ISender*>;
		template<typename T>
		class OnMiddleMouseClick
		{
		public:
			OnMiddleMouseClick(ISender* sender, IEventMessageReceiver* receiver, ClickEventType::EventHandlerType* eventHandler = nullptr)
				: m_messager(sender, receiver, eventHandler)
			{};

			auto& getMiddleMouseClickEvent() {
				return m_messager;
			}

			void sendMiddleMouseClickEvent() {
				if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(2)) {
					onMiddleMouseClick();
				}
			}

			virtual void onMiddleMouseClick() {
				m_messager.invoke(m_messager.getSender());
			}
		private:
			ClickEventType m_messager;
		};
		
		using CloseEventType = Event<ISender*>;
		template<typename T>
		class OnClose
		{
		public:
			OnClose(ISender* sender, IEventMessageReceiver* receiver, CloseEventType::EventHandlerType* eventHandler = nullptr)
				: m_messager(sender, receiver, eventHandler)
			{};

			auto& getCloseEvent() {
				return m_messager;
			}

			void sendCloseEvent() {
				onClose();
			}

			virtual void onClose() {
				m_messager.invoke(m_messager.getSender());
			}
		private:
			CloseEventType m_messager;
		};
	};
};