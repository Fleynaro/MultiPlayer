#include <iostream>
#include <fstream>
#include <Windows.h>

using namespace std;

/*
    При разрабокте оттакливаемся от производительности вставки записей. Для этого:
    1) Избегаем мьютексов
    2) Делаем много потоков - workers. 
    3) Делаем эффективного менеджера(одного, нет раздедения на арг и рет)
    4) Каждый worker работает со своим буфером
    5) Может случиться, что каждый worker будет потом занят записью содержимого буфера в файл. Тогда будут серьезные подвисания.
        Решение: создать вспомогательные потоки, которые будут спать и просыпаться по запросу менеджера. Если worker заполнен, то забираем у него буфер и передаем спящему потоку(можно одному, у него очередь буферов на запись в файл)

    !!!ВАРИАНТ 2: есть один активный буфер. В него производятся записи. Если буфер заполнился, то отправляем его в очердь на запись в файл в разные потоки. Просто создаем поток новый. Новый активный буфер выделяется в памяти.


    Также создадим свой ByteStream. Его задача - упаковывать компактно данные о вызовах. Соблюдать выравнивание, ибо лучше записывать словами в память, чем байтами!
    Заголовки:  [тип записи: before/after call] [id триггера] [id функции] [unixtime] [guid] [запись битами сюда общей инфы: есть ли строка, есть ли указ,массив - нужно для поиска]
                before: [кол-во аргументов N] [список типов(byte,int,char,object) для каждого аргумента + [pointer/not pointer] N - 4 бита] [сами аргументы N]
                аргумент число int - 4 байта
                аргумент char[32](это pointer, проверяем на массив) - [адрес массива] [число символов] [raw string]
                аргумент float[4] - то же, что и вверху. это массив. макс. число элементов 65535
                ...
                опционально записываем фрагмент стека нужного размера

    В итоге у нас будет папка, где будет куча файлов-буферов. Сделать анализатор этих файлов:
    1) Анализ типов значений
    2) Анализ строк
    3) Аанализ объектов: например где этот объект вызывался, где изменялся и т.д
    4) Встречалось ли какое-то значение в стеке(строка)

    Для каждого типа анализа свой класс, у каждого свои результаты. Некоторые можно сохранить в БД

*/

class Buffer
{
    struct Header {
        int m_contentSize;
        int m_currentOffset;
    };
public:
    Header m_header;

private:
    void init(int size) {
        m_header.m_contentSize = size;
        m_header.m_currentOffset = 0;
    }

public:
    static Buffer* Create(int size) {
        auto buffer = (Buffer*)(new BYTE[size]);
        buffer->init(size);
        return buffer;
    }

    static void Destroy(Buffer* buffer) {
        delete[] (BYTE*)buffer;
    }

    inline BYTE* getData() {
        return (BYTE*)&m_header;
    }

    inline BYTE* getContent() {
        return (BYTE*)((std::uintptr_t) &m_header + sizeof(m_header));
    }

    int getSize() {
        return sizeof(m_header) + m_header.m_contentSize;
    }

    int getCurrentOffset() {
        return sizeof(m_header) + m_header.m_currentOffset;
    }

    int getFreeSpaceSize() {
        return getSize() - getCurrentOffset();
    }

    class Stream {
    public:
        Stream(Buffer* buffer)
            : m_buffer(buffer)
        {
            setNext(m_buffer->getContent());
        }

        template<typename T = BYTE>
        inline void write(const T& data) {
            if (!isFree<T>())
                return;
            (T&)*m_curData = data;
            m_curData += sizeof(T);

            if(m_buffer->m_header.m_currentOffset < getOffset() + sizeof(T))
                m_buffer->m_header.m_currentOffset = getOffset() + sizeof(T);
        }

        template<typename T = BYTE>
        inline T& read() {
            if (!isFree<T>())
                throw std::exception("No free space in the buffer.");
            auto& data = (T&)*m_curData;
            m_curData += sizeof(T);
            return data;
        }

        template<typename T = BYTE>
        inline bool isFree() {
            return m_buffer->getFreeSpaceSize() >= sizeof(T);
        }

        inline BYTE* getNext() {
            return m_curData;
        }

        inline void setNext(BYTE* ptr) {
            m_curData = ptr;
        }
    private:
        Buffer* m_buffer;
        BYTE* m_curData;

        int getOffset() {
            return (int)((std::uintptr_t)m_curData - (std::uintptr_t)m_buffer->getContent());
        }
    };

    friend class Stream;
};


int main()
{
    auto buf = Buffer::Create(1024 * 1024 * 3);

    struct CallInfo {
        uint64_t m_args[10000];
    };

    {
        auto st = Buffer::Stream(buf);

        auto ptr = st.getNext();
        st.write(5);

        CallInfo obj;
        obj.m_args[0] = 0xA1;
        obj.m_args[1000] = 0xA2;
        st.write(obj);
        st.write(5);

        st.setNext(ptr);
        st.write(8);
    }

    ofstream output_file("buffer.data", ios::binary);
    if (!output_file.is_open())
        return 0;

    output_file.write((char*)buf->getData(), buf->getSize());
    output_file.close();

    Buffer::Destroy(buf);

    ifstream file("buffer.data", ios::binary);
    if (!file.is_open())
        return 0;

    auto buf2 = Buffer::Create(1024 * 1024 * 3);
    file.read((char*)buf2->getData(), buf2->getSize());
    file.close();

    {
        auto st = Buffer::Stream(buf2);
        auto ll = st.read<int>();
        CallInfo& obj = st.read<CallInfo>();
        uint64_t a1 = obj.m_args[0];
        uint64_t a2 = obj.m_args[1];
        
        if (st.isFree()) {

        }
    }

    system("pause");
}