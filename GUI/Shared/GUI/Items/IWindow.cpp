#include "IWindow.h"

using namespace GUI;

void Events::EventUI::callHandler(EventMessage::Type message) {
	if (message->getSender()->isGuiItem()) {
		auto sender = ((Item*)message->getSender());
		
		auto win = sender->getWindow();
		sender->getWindow()->addEventMessage(message);
	}
	else {
		m_eventMessages.push_back(message);
	}
}