#pragma once
#include <string>
#include <algorithm>
#include <cctype>
#include <cstddef>
class String {
  std::string v;
public:
  String() = default;
  String(const char* s) : v(s ? s : "") {}
  String(const std::string& s):v(s){}
  String(unsigned int i):v(std::to_string(i)){}
  String(int i):v(std::to_string(i)){}
  const char* c_str() const {return v.c_str();}
  char operator[](std::size_t i) const {return v[i];}
  std::size_t length() const {return v.size();}
  bool isEmpty() const {return v.empty();}
  bool startsWith(const char* p) const {return v.rfind(p,0)==0;}
  bool equalsIgnoreCase(const String& other) const {
    if(v.size()!=other.v.size())return false;
    for(std::size_t i=0;i<v.size();++i) if(std::tolower((unsigned char)v[i]) != std::tolower((unsigned char)other.v[i])) return false;
    return true;
  }
  bool operator==(const String& o) const {return v==o.v;}
  bool operator!=(const String& o) const {return v!=o.v;}
  String operator+(const String& o) const {return String(v+o.v);}
  friend String operator+(const char* c,const String& o){return String(std::string(c)+o.v);}
};
