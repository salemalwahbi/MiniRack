#pragma once
#include "Arduino.h"
#include <unordered_map>
#include <string>
class Preferences {
  std::unordered_map<std::string,String> store;
public:
  String getString(const char* key,const char* def="") {auto it=store.find(key);return it==store.end()?String(def):it->second;}
  bool getBool(const char* key,bool def=false) {auto it=store.find(key);return it==store.end()?def:it->second==String("1");}
  std::size_t putString(const char* key,const String& val) {store.insert_or_assign(key,val);return val.length();}
  std::size_t putBool(const char* key,bool v) {store.insert_or_assign(key,String(v?"1":"0"));return 1;}
  bool remove(const char* key) {return store.erase(key)>0;}
};
