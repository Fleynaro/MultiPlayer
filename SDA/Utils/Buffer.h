#pragma once
#include <main.h>

class BufferOverflowException : public std::exception
{

};

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

    int getContentSize() {
        return m_header.m_contentSize;
    }

    int getContentOffset() {
        return m_header.m_currentOffset;
    }

    int getFreeSpaceSize() {
        return getContentSize() - getContentOffset();
    }

    class Stream {
    public:
        Stream() = default;

        Stream(Buffer* buffer)
            : m_buffer(buffer)
        {
            setNext(m_data = m_buffer->getContent());
        }

        Stream(Stream* bufferStream)
            : m_bufferStream(bufferStream), m_buffer(bufferStream->m_buffer)
        {
            setNext(m_data = m_bufferStream->getNext());
        }

        template<typename T = BYTE>
        inline Stream& write(const T& data) {
            if (!isFree(sizeof(T))) {
                throw BufferOverflowException();
                return *this;
            }
            (T&)*m_curData = data;
            move(sizeof(T), true);
            return *this;
        }

        inline Stream& writeFrom(void* addr, int size) {
            if (!isFree(size)) {
                throw BufferOverflowException();
                return *this;
            }
            memcpy_s(m_curData, m_buffer->getFreeSpaceSize(), addr, size);
            move(size, true);
            return *this;
        }

        template<typename T = BYTE>
        inline T& read() {
            return *readPtr<T>();
        }

        template<typename T = BYTE>
        inline T* readPtr(int size = sizeof(T)) {
            if (!isFree(size))
                throw std::exception("No free space in the buffer.");
            auto data = (T*)m_curData;
            m_curData += size;
            return data;
        }

        inline bool isFree(int size) {
            return m_buffer->getFreeSpaceSize() >= size;
        }

        void move(int bytes, bool write = false) {
            m_curData += bytes;

            if (write) {
                if (m_buffer->m_header.m_currentOffset < getOffset())
                    m_buffer->m_header.m_currentOffset = getOffset();
            }

            if (m_bufferStream != nullptr)
                m_bufferStream->move(bytes, write);
        }

        template<typename T = BYTE>
        inline T* getNext() {
            if (!isFree(sizeof(T))) {
                //throw BufferOverflowException();
            }
            return (T*)m_curData;
        }

        template<typename T = BYTE>
        inline void setNext(T* ptr) {
            m_curData = (BYTE*)ptr;
        }

        int getOffset() {
            return (int)((std::uintptr_t)m_curData - (std::uintptr_t)m_data);
        }
    private:
        Buffer* m_buffer;
        BYTE* m_data;
        BYTE* m_curData;

        Stream* m_bufferStream = nullptr;
    };

    friend class Stream;
};