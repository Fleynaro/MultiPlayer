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

int main2()
{
	g_program = new Program(GetModuleHandle(NULL));
	DebugOutput_Console = false;
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	printf("SDA module executing\n\n");
	using namespace CE;

	std::string pathh = "D:\\MultiPlayer\\MultiPlayer\\SDA\\Databases";
	if (!FS::Directory(pathh).exists()) {
		pathh = "R:\\Rockstar Games\\MULTIPLAYER Dev\\MultiPlayer\\MultiPlayer\\SDA\\Databases";
	}

	Hook::init();

	ProgramExe* sda = new ProgramExe(GetModuleHandle(NULL), FS::Directory(pathh));
	try {
		sda->initDataBase("database.db");
		sda->initManagers();
		sda->initGhidraClient();
		sda->load();

		auto declManager = sda->getFunctionManager()->getFunctionDeclManager();
		auto function = sda->getFunctionManager()->createFunction(&setRot2, { Function::AddressRange(&setRot2, 200) }, declManager->createFunctionDecl("setRot", "get rot of entity"));
		auto functiondb2 = sda->getFunctionManager()->createFunction(&changeGvar2, { Function::AddressRange(&changeGvar2, 40) }, declManager->createFunctionDecl("changeGvar", ""));
		auto functiondb3 = sda->getFunctionManager()->createFunction(&rand, { Function::AddressRange(&rand, 300) }, declManager->createFunctionDecl("rand", ""));
		auto functiondb5 = sda->getFunctionManager()->createFunction(&setPlayerPos2, { Function::AddressRange(&setPlayerPos2, 10) }, declManager->createFunctionDecl("setPlayerPos", ""));
		auto functiondb6 = sda->getFunctionManager()->createFunction(&setPlayerVel2, { Function::AddressRange(&setPlayerVel2, 10) }, declManager->createFunctionDecl("setPlayerVel", ""));
		
		//sda->getFunctionManager()->saveFunction(*functiondb2->getFunction());

		sda->getFunctionManager()->buildFunctionBodies();
	

		{
			using namespace CallGraph;
			CallGraphIterator iter(sda->getFunctionManager());
			iter.iterate([&](Node::Node* node, CallStack& stack)
			{
				/*if (!node->isFunctionBody() && !node->isVMethod() && !node->isGlobalVar())
					return true;

				std::string line = "";
				for (int i = 0; i < stack.size(); i++)
					line += "-";
				line += " ";

				if (node->isFunctionBody()) {
					if (stack.size() == 1) {
						line += ">>> ";
					}
					auto funcBody = static_cast<Node::FunctionBody*>(node);
					line += funcBody->getFunction()->getName();
				}
				if (node->isGlobalVar()) {
					line += "gVar";
				}
				if (node->isVMethod()) {
					line += "vMethod";
				}

				line += "\n";
				printf(line.c_str());*/
				return true;
			});
		}

		auto fMan = sda->getFunctionManager();

		Function::Tag::Manager manager(sda->getFunctionManager());
		manager.loadTags();
		manager.calculateAllTags();
		auto collection = manager.getTagCollection(functiondb5);

		/*CallGraph::Analyser::ContextDistance analysis2(sda->getFunctionManager(), functiondb5->getBody(), functiondb6->getBody());
		analysis2.doAnalyse();*/

		function->createHook();
		auto hook = function->getHook();
		hook->getDynHook()->enable();

		auto trigger = sda->getTriggerManager()->createFunctionTrigger("for filtering");
		//auto filter1 = new Trigger::Function::Filter::Object(nullptr);
		//auto filter1 = new Trigger::Function::Filter::Empty;
		auto filter1 = new Trigger::Function::Filter::Cmp::Argument(1, 1, Trigger::Function::Filter::Cmp::Eq);
		//auto filter1 = new Trigger::Function::Filter::Cmp::RetValue(12, Trigger::Function::Filter::Cmp::Eq);

		//trigger->setStatCollectingEnable(sda->getStatManager()->getCollector());
		trigger->getFilters()->addFilter(filter1);
		hook->addActiveTrigger(trigger);

		setRot2(1, 2, 3, 4, 5);
		setRot2(1, 2.6, 3.7, 4.8, 500);
		setRot2(1, 20, 30, 400, 50000);

		system("pause");
		return 0;

		//sda->getTriggerManager()->saveTrigger(trigger);
		//sda->getTriggerManager()->loadTriggers();

		if(false)
		{
			/*using namespace CE::Stat::Function;
			Account account(&sda->getStatManager()->getDB(), function);
			account.iterateCalls([&](Account::CallInfo& info) {
				printf("callId = %llu: %i,%i,%i,%i(float %f,%f,%f,%f) => %i(float %f)\n", info.m_uid, info.m_args[0], info.m_args[1], info.m_args[2], info.m_args[3], info.m_xmm_args[0], info.m_xmm_args[1], info.m_xmm_args[2], info.m_xmm_args[3], info.m_ret, info.m_xmm_ret);
				}, trigger, 1);

			auto statInfo = account.createStatInfo(trigger);
			statInfo->debugShow();
			return 0;*/
		}
		//return;
		//CE::Trigger::Function::callback_before(hook->getDynHook(), 0);
		//CE::Trigger::Function::callback_before(hook->getDynHook(), 0);

		/*CE::Hook::DynHook::newCallState();
		CE::Hook::DynHook::newCallState();*/

		//int result = setRot(9, -10, 11, -12, 13);
//		setRot(10, 11, 12);


		//std::thread t([&] {
		//	auto hook = new CE::Hook::DynHook;
		//	hook->setUserPtr(function);
		//	while (true) {
		//		CE::Trigger::Function::callback_before(hook, 0);
		//	}
		//	});
		//t.detach();

		//printf("%i\n", result);

		
		for (int i = 0; i < 1; i++)
		{
			std::thread t([i] {
				for (int j = 0; j < 10; j++) {
					setRot2(10 + j, -10.f, 10.f, 888.4f, 999);
					//Sleep(1);
				}
				});
			t.detach();
		}

		Sleep(2000);
		printf("\n\nupdateGeneralDB\n");
		
		//sda->getFunctionManager()->saveFunction(function);
		//sda->getFunctionManager()->saveFunctionArguments(function);

		auto method = sda->getFunctionManager()->getFunctionById(3);


		printf("%s | %s\n", method->getSigName().c_str(), sda->getTypeManager()->getTypeById(11)->getName());
	}
	catch (std::exception& e) {
		DebugOutput("exception: " + std::string(e.what()));
	}


	/*Type::Class* entity = new Type::Class(100, "Entity");

	Function::Method* setPos = new Function::Method(nullptr, 0, 50, "setPos");
	setPos->getSignature().setReturnType(new Type::Void);
	setPos->addArgument(nullptr, "This");
	setPos->addArgument(new Type::Float, "x");
	setPos->addArgument(new Type::Float, "y");
	setPos->addArgument(new Type::Float, "z");
	entity->addMethod(setPos);

	Function::Method* setVel = new Function::Method(nullptr, 0, 50, "setPos");
	setVel->getSignature().setReturnType(new Type::Void);
	setVel->addArgument(nullptr, "This");
	setVel->addArgument(new Type::Float, "x");
	setVel->addArgument(new Type::Float, "y");
	setVel->addArgument(new Type::Float, "z");
	entity->addMethod(setVel);

	entity->iterateMethods([](Function::Method* method) {
		printf("%s\n", method->getSigName().c_str());
	});*/

	printf("\n\n");
	return 0;
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