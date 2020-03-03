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

namespace Buffer {
    class IBlock {
    public:
        virtual BYTE* getData() = 0;
        virtual int getSize() = 0;
    };

    template<int BlockSize>
    class Block : public IBlock {
        struct Header {
            int m_contentSize;
        };

    protected:
        Header m_header;
        BYTE m_content[BlockSize];
    public:
        Block() {
            m_header.m_contentSize = sizeof(m_content);
        }

        BYTE* getData() override {
            return (byte*)&m_header;
        }

        int getSize() override {
            return sizeof(m_header) + sizeof(m_content);
        }
    };

    template<typename T>
    class Type : public Block<sizeof(T)> {
        using Block = Block<sizeof(T)>;
    public:
        Type() = default;

        T& operator*() {
            return (T&)Block::m_content;
        }
    };


    class IBuffer {
    public:
        virtual BYTE* getData() = 0;
        virtual BYTE* getContent() = 0;
        virtual int getSize() = 0;
        virtual int getCurrentOffset() = 0;
        virtual int getFreeSpaceSize() = 0;
        virtual void addBlock(IBlock& block) = 0;
    };

    template<int BufferSize>
    class Buffer : public IBuffer
    {
        struct Header {
            int m_contentSize;
            int m_blockCount;
            int m_currentOffset;
        };
    public:
        Header m_header;
        BYTE m_content[BufferSize];

        Buffer() {
            m_header.m_contentSize = sizeof(m_content);
            m_header.m_blockCount = 0;
            m_header.m_currentOffset = 0;
        }

        BYTE* getData() override {
            return (byte*)&m_header;
        }

        BYTE* getContent() override {
            return m_content;
        }

        int getSize() override {
            return sizeof(m_header) + sizeof(m_content);
        }

        int getCurrentOffset() override {
            return sizeof(m_header) + m_header.m_currentOffset;
        }

        int getFreeSpaceSize() override {
            return getSize() - getCurrentOffset();
        }

        void addBlock(IBlock& block) override {
            auto addr = (std::uintptr_t)&m_content + getCurrentOffset();
            memcpy_s((void*)addr, getFreeSpaceSize(), &block, block.getSize());
            m_header.m_blockCount++;
            m_header.m_currentOffset += block.getSize();
        }
    };

    class Iterator {
    public:
        Iterator(IBuffer* buffer)
            : m_buffer(buffer)
        {}

        bool hasNext() {

        }

        IBlock& next() {
            auto block = (IBlock*)((std::uintptr_t)m_buffer->getContent() + m_offset);
            m_offset += block->getSize();
            return *block;
        }
    private:
        IBuffer* m_buffer;
        int m_offset = 0;
    };
};


int main()
{
    Buffer::IBuffer* buffer = new Buffer::Buffer<1024 * 1024 * 2>;
    
    struct CallInfo {
        uint64_t m_args[10];
    };

    {
        Buffer::Type<CallInfo> block;
        (*block).m_args[1] = 0xAA;
        buffer->addBlock(block);
    }

    ofstream output_file("buffer.data", ios::binary);
    output_file.write((char*)buffer->getData(), buffer->getSize());
    output_file.close();

    fstream file("buffer.data", ios::binary);
    Buffer::IBuffer* buffer2 = new Buffer::Buffer<1024 * 1024 * 2>;
    file.read((char*)buffer->getData(), buffer->getSize());
    file.close();

    {
        Buffer::Type<CallInfo> block;
        
    }

    system("pause");
}