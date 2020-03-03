#include <iostream>
#include <fstream>
#include <Windows.h>

using namespace std;


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