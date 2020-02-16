#include "IWindow.h"

using namespace GUI;

void Events::EventUI::callHandler(EventMessage::Type message) {
	if (message->getSender()->isGuiItem()) {
		auto sender = static_cast<Item*>(message->getSender());
		sender->getWindow()->addEventMessage(message);
	}
	else {
		m_eventMessages.push_back(message);
	}
}