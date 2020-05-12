#include <Program.h>
#include <SdaInterface.h>
#include <FunctionTag/FunctionTag.h>

Program* g_program = nullptr;


int setRot2(int a, float x, float y, float z, int c);

class SomeClass2
{
public:
	virtual int getValue() {
		return 4;
	}
};

auto g_someClass2 = new SomeClass2;
int g_IntegerVal2 = 4;

void setPlayerPos2() {
	g_IntegerVal2 = 5;
}

void setPlayerVel2() {
	int a = 5;
}

float gVar2 = 0;
void changeGvar2() {
	gVar2 = 2.0;
	setPlayerVel2();
}

int setRot2(int a, float x, float y, float z, int c)
{
	if (a <= 2) {
		int result = setRot2(a + 1, x, y, z, c);
	}
	g_IntegerVal2 = 100;
	float result = x + y + z + a + c + g_someClass2->getValue();
	result = pow(result, 1);
	setPlayerPos2();
	gVar2 = float(rand() % 10);
	changeGvar2();
	return result;
}

//MY TODO*: 1) сделать древовидный анализ через теги типа get/set; сделать менеджер
//MY TODO*: 1.1) 
//MY TODO*: 2) GUI сделать отображение дерева вызовов для функции с фильтром(наличие переменных, вирт. вызовов, collapse all btn)
//MY TODO*: 3) редактор сигнатуры функций. для этого определить по каком аргументу/типу кликнули
//MY TODO*: 3.1) сделать высвечивающееся окошко с типами как в гидре
//MY TODO*: 4) вызов функций с параметрами. параметры: обычные типы, указатели на классы, сами классы(стек) и enum
//MY TODO*: 4.1) сделать менеджер для экземпляров класса, где мы указываем сами значения полей. выделяется в куче и хранится.
//MY TODO*: 5) сделать редактор классов такой же как и в ReClass. + указывать pointer на класс в памяти, должны подсвечиваться значения. Но тут также есть и методы еще. Предлагается сделать редактор в виде текста кода
//MY TODO*: 6) сохранение настроек юзера в отдельной БД
//MY TODO*: 6.1) сохранение состояния фильтров поиска(есть combo box и кнопка сохранить с названием от юзера)
//MY TODO*: 6.2) сохранение указанных состояний списка параметров для вызова функций
//MY TODO*: 7) триггеры. сделать менеджер. в одном триггере может быть несколько функций(выбор через спец. виджет combobox + search) + указание в нем списка фильтров и действий
//MY TODO*: 7.1) к каждому триггеру прикладывается статистика вызовов функций, где строится гистограмма и тд
//MY TODO*: 8) Менеджер шрифтов для GUI
//MY TODO*: 9) Всевозможные виды анализов
//MY TODO*: 9.1) Наличие общих функций у двух функций
//MY TODO*: 9.2) Нахождение кратчайшего пути для 2-х функций в графе вызовов


//MY TODO*: 10) Все виджеты - контейнеры. Любое добавление свойств к элементам UI - наследование.
//MY TODO*: 10.1) FilterConditionList - реализовать функцию render
//MY TODO*: 10.2) Ленивая иницилизация для элементов интерфейса. Если не показыватся - не создавать. Юзать что-то типа beginImGui.
//MY TODO*: 10.3) ToolDesc - есть 2 типа, текстовый и контейнер(shortcut, контекстное меню). Это отдельные классы. Они цепляются к любому элементу UI. Для этого юзаем аттрибут Attribute::ToolDesc, Attribute::ContextMenu. Уникально для каждого элемента и появляется при hover!
//MY TODO*: 10.4) Для каждого элемента(или глобально) создать таймер - вирт. метод timer и вызывать вне зависимости от isShow
//MY TODO*: 10.5) В таймере удалять временно созданные объекты. Нужно для 10.2: помечать как допускающее удаление последующее(ITemporable); например, сигнатура функции
//MY TODO*: 10.6) больше вразумительных событий: onHoverIn, onHoverOut(юзаются в toolDesc: create и remove); onShow, onHide(ленивая иницилизация)
//MY TODO*: 10.6.1) Можно просто по событию hover создать/показать(если передался) tooldesc, держать в памяти до hoverOut и delete. Т.е. вручную управляем
//MY TODO*: 10.7) context menu - по пкм
//MY TODO*: 10.8) address viewer(link) and copy to clipboard

//MY TODO*: 11) Функции WinApi, directx и других либ можно поставлять в базовом наборе и сразу для них получать адрес

/*
	Важно: время жизни объектов UI <= время жизни сущностей программы -> значит можно хранить указатели на объекты не хадумываясь
*/

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DebugOutput("sda.dll loaded successfully!");
		g_program = new Program(hModule);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}