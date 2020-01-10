#pragma once

//for class building to export c++ method
#define SET_METHOD_LINK(method) ->setLink<__COUNTER__, decltype(##method)>(##method)
#define SET_ACCESSOR_LINK(type, method) ->setLinkTo##type<__COUNTER__, decltype(##method)>(##method)
#define SET_ENUM(Class, EnumType, EnumName) (new Enum(##EnumName))->setLink<##EnumType>()->addItems(getEnum(##Class, ##EnumName))

#define STANDART_LUA_ACCESSOR_FILTER(classType) Filter<##classType>::lua_getter, Filter<##classType>::lua_setter
#define STANDART_LUA_DESTRUCTOR(classType) Filter<##classType>::lua_delete