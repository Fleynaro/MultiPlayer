#pragma once
#include <main.h>

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
        delete[](BYTE*)buffer;
    }

    inline BYTE* getData() {
        return (BYTE*)&m_header;
    }

    inline BYTE* getContent() {
        return (BYTE*)((std::uintptr_t) & m_header + sizeof(m_header));
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
        inline Stream& write(const T& data) {
            if (!isFree<T>())
                return *this;
            (T&)*m_curData = data;
            m_curData += sizeof(T);

            if (m_buffer->m_header.m_currentOffset < getWrittenLength() + sizeof(T))
                m_buffer->m_header.m_currentOffset = getWrittenLength() + sizeof(T);
            return *this;
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

        int getWrittenLength() {
            return (int)((std::uintptr_t)m_curData - (std::uintptr_t)m_buffer->getContent());
        }
    private:
        Buffer* m_buffer;
        BYTE* m_curData;
    };

    friend class Stream;
};