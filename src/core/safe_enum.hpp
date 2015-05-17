#ifndef safe_enum_hpp
#define safe_enum_hpp
/*
 * Strongly-Typed Enums.
 * 
 * Avoids accidental implicit coercion.
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
template<typename def, typename inner = typename def::type>
class safe_enum : public def
{
public:
  typedef inner type;
  inner val;
 
  safe_enum() {}
  safe_enum(type v) : val(v) {}
  safe_enum(safe_enum<def,inner> const& v) : val(v.val) {}

  type underlying() const { return val; }
 
  friend bool operator == (const safe_enum & lhs, const safe_enum & rhs) { return lhs.val == rhs.val; }
  friend bool operator != (const safe_enum & lhs, const safe_enum & rhs) { return lhs.val != rhs.val; }
  friend bool operator <  (const safe_enum & lhs, const safe_enum & rhs) { return lhs.val <  rhs.val; }
  friend bool operator <= (const safe_enum & lhs, const safe_enum & rhs) { return lhs.val <= rhs.val; }
  friend bool operator >  (const safe_enum & lhs, const safe_enum & rhs) { return lhs.val >  rhs.val; }
  friend bool operator >= (const safe_enum & lhs, const safe_enum & rhs) { return lhs.val >= rhs.val; }
};

#endif