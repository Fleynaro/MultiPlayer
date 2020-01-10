#pragma once



namespace SDK::UI {
	class Item
	{
	public:
		Item() {

		}
		virtual ~Item() {}
		virtual void draw(float screenWidth, float screenHeight) = 0;

		void show(float screenWidth, float screenHeight) {
			if (isShown()) {
				draw(screenWidth, screenHeight);
			}
		}

		void setDisplay(bool state) {
			m_display = state;
		}

		bool isShown() {
			return m_display;
		}
	private:
		bool m_display = true;
	};
};