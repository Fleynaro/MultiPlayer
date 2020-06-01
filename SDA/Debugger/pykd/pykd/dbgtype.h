#pragma once

#include <string>
#include <map>

#include "dbgmem.h"
#include "dbgsystem.h"

#include <boost/python/slice.hpp>

///////////////////////////////////////////////////////////////////////////////////

class TypedVar;
class TypeInfo;

///////////////////////////////////////////////////////////////////////////////////

class TypeInfo {

public:

     TypeInfo() :
        m_size(0),
        m_arraySize( 0 ),
        m_parentOffset( 0 ), 
        m_align( 0 ),
        m_isFreezed( false ),
        m_isBaseType( false ),
        m_isPointer( false ),
        m_alignReq(1)
        {}

     TypeInfo( const std::string customName, ULONG align = 0) :
        m_typeName( customName ),
        m_size( 0 ),
        m_arraySize( 0 ),
        m_parentOffset( 0 ),
        m_isFreezed( false ),
        m_align( align ),
        m_isBaseType( false ),
        m_isPointer( false ),
        m_alignReq(1)
        {}

     TypeInfo( const std::string &moduleName, const std::string  &typeName );

     TypeInfo( const std::string &moduleName, ULONG64 moduleBase, ULONG typeId );

     static
     const TypeInfo&
     get( const std::string &moduleName, const std::string  &typeName );

     ULONG
     size() const {
        return m_size;
     }

     ULONG
     count() const {
        assert( m_size != 0 && m_arraySize >= m_size );
        return m_arraySize / m_size;
     }

     ULONG
     fullSize() const {
        return m_arraySize;
     }

     const std::string
     name() const {
        return m_typeName;
     }

     const std::string
     moduleName() const {
        return m_moduleName;
     }

     boost::python::object
     load( void* buffer, size_t  bufferLength ) const;

     std::string
     printField( size_t index, void* buffer, size_t  bufferLength ) const;

     std::string
     print() const;
     
     TypeInfo
     getField( const std::string  &fieldName ) const;

     TypeInfo
     getFieldAt( size_t  index ) const;

     ULONG
     getFieldOffset() const {
        return  m_parentOffset;
     }  

     boost::python::object
     getFieldByIndex( boost::python::object &index ) const;   

     size_t
     getFieldCount() const {
        return m_fields.size();
     }

     void
     appendField( const TypeInfo &typeInfo, const std::string &fieldName, ULONG count = 1 );

     bool
     isBaseType() const {
        return m_isBaseType;
     }

     bool
     isPtr() const {
        return m_isPointer;
     }

     bool
     isEnum() const {
        return !m_isBaseType && !m_isPointer && m_fields.size() == 0 && m_size == 4;
     }

     boost::python::object
     loadVar( ULONG64  targetOffset, ULONG count = 1) const;

     void setAlignReq(ULONG alignReq) {
         m_alignReq = alignReq;
     }

public:

    typedef std::map< std::pair<std::string, std::string>, TypeInfo>        TypeInfoMap;
    
    template< typename TTypeInfo>
    struct TypeFieldT {
    
        std::string     name;
        
        ULONG           offset;
        
        ULONG           size;
        
        TTypeInfo       type;
        
        TypeFieldT( const std::string &name_, const TTypeInfo  &type_,  ULONG size_, ULONG offset_ ) :
            name( name_ ),
            size( size_ ),
            offset( offset_ ),
            type( type_ )               
            {}        
            
        std::string print() const;
    };
    
    typedef TypeFieldT<TypeInfo>        TypeField;

    typedef std::vector<TypeField>      TypeFieldList;

private:

    ULONG getAlignReq() const;

    void addField(
        const std::string &name_,
        const TypeInfo  &type_,
        ULONG size_,
        ULONG offset_
    );

    typedef
    boost::python::object
    (*basicTypeLoader)( void* address, size_t size );

    typedef 
    std::string
    (*basicTypePrinter)( void* address, size_t size );

    static TypeInfoMap          g_typeInfoCache; 

    static const char*          basicTypeNames[];

    static size_t               basicTypeSizes[]; 

    static basicTypeLoader      basicTypeLoaders[];

    static basicTypePrinter     basicTypePrinters[];

    ULONG                       m_size;     

    ULONG                       m_arraySize;

    std::string                 m_typeName;

    std::string                 m_moduleName;

    TypeFieldList               m_fields;

    bool                        m_isPointer;

    bool                        m_isBaseType;

    bool                        m_isFreezed;

    ULONG                       m_align;

    ULONG                       m_alignReq;

    ULONG                       m_parentOffset;

    static bool  checkBaseType( const std::string  &typeName );

    static ULONG  getBaseTypeSize( const std::string  &typeName );
};


///////////////////////////////////////////////////////////////////////////////////

class TypedVar {

public:
    
    TypedVar() :
        m_targetOffset ( 0 )
        {}

    TypedVar( const TypeInfo  &typeInfo, ULONG64 targetOffset ) :
        m_typeInfo( typeInfo ),
        m_targetOffset( addr64(targetOffset) )
        {}
        
    TypedVar( const std::string &moduleName, const std::string &typeName, ULONG64 targetOffset ) :
        m_typeInfo( moduleName, typeName ),
        m_targetOffset( addr64(targetOffset) )
        {}        

    TypedVar( ULONG64 targetOffset );

    TypedVar( const std::string &symbolName );
        
    ULONG64
    getAddress() const {
        return m_targetOffset;
    }     

    ULONG
    getSize() const {
        return m_typeInfo.fullSize();
    }
    
    static
    boost::python::object
    getFieldWrap( PyObject* self, const std::string  &fieldName );
    
    boost::python::object
    getField( boost::python::object  &pyobj, const std::string  &fieldName ); 
    
    ULONG64 getTargetOffset() const {
        return m_targetOffset;
    }      
    
    std::string data();
    
    std::string print();
        
private:

    void reallocBuffer();

    TypedVar( const TypeInfo &typeInfo, ULONG64 targetOffset, char* buffer, size_t bufferLength );
  
    ULONG64                 m_targetOffset;  

    TypeInfo                m_typeInfo;    

    std::vector<char>       m_buffer;
};

///////////////////////////////////////////////////////////////////////////////////    

boost::python::object
loadTypedVarList( ULONG64 address, const std::string &moduleName, const std::string &typeName, const std::string &listEntryName );

boost::python::object
loadTypedVarArray( ULONG64 address, const std::string &moduleName, const std::string &typeName, long number );

boost::python::object
containingRecord( ULONG64 address, const std::string &moduleName, const std::string &typeName, const std::string &fieldName );

ULONG
sizeofType( const std::string &moduleName, const std::string &typeName );

///////////////////////////////////////////////////////////////////////////////////    

