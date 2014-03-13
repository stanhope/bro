#ifndef HASH_FUNC_C
#define HASH_FUNC_C
#include <functional>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <string.h>

#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
		      +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

#define DWORD_HAS_ZERO_BYTE(V) (((V) - 0x01010101UL) & ~(V) & 0x80808080UL)

#define SEED 0xc70f6907UL
#define CONST_M 0x5bd1e995

using namespace std;

/*
 * Define hash algorithms that are explicitly set in the template
 */

inline uint32_t SuperFastHash(string str, int len)
{
  uint32_t hash = len, tmp;
  int rem;
  const char *data = str.c_str();

  rem = len & 3;
  len >>= 2;

  /* Main loop */
  for(; len > 0; len--)
    {
      hash += get16bits(data);
      tmp = (get16bits(data + 2) << 11) ^ hash;
      hash = (hash << 16) ^ tmp;
      data += 2 * sizeof(uint16_t);
      hash += hash >> 11;
    }

  /* Handle end cases */
  switch(rem)
    {
    case 3: hash += get16bits(data);
      hash ^= hash << 16;
      hash ^= ((signed char) data[sizeof(uint16_t)]) << 18;
      hash += hash >> 11;
      break;
    case 2: hash += get16bits(data);
      hash ^= hash << 11;
      hash += hash >> 17;
      break;
    case 1: hash += (signed char) *data;
      hash ^= hash << 10;
      hash += hash >> 1;
    }

  /* Force "avalanching" of final 127 bits */
  hash ^= hash << 3;
  hash += hash >> 5;
  hash ^= hash << 4;
  hash += hash >> 17;
  hash ^= hash << 25;
  hash += hash >> 6;

  return hash;
}

inline uint32_t FNV1A_Hash_Jesteress(string sStr, int len)
{
  const uint32_t PRIME = 709607;
  uint32_t hash32 = 2166136261;
  const char *p = sStr.c_str();

  for(;;)
    {
      uint32_t dw1 = *(uint32_t *) p;
      if (DWORD_HAS_ZERO_BYTE(dw1))
	break;

      p += 4;
      //        hash32 = hash32 ^ _lrotl(dw1,5);
      hash32 = hash32 ^ ((dw1 << 5) | (dw1 >> (sizeof(uint32_t) * 3)));

      uint32_t dw2 = *(uint32_t *) p;
      if (DWORD_HAS_ZERO_BYTE(dw2))
	{ // finish dw1 without dw2
	  hash32 *= PRIME;
	  break;
	}

      p += 4;

      hash32 = (hash32 ^ dw2) * PRIME;
    }

  while(*p)
    {
      hash32 = (hash32 ^ *p) * PRIME;
      p++;
    }

  return hash32;
}


inline uint32_t Murmor(string sStr, int len)
{
  uint32_t hash = SEED ^ len;
  const char *data = sStr.c_str();

  // Mix 4 bytes at a time into the hash.
  while(len >= 4)
    {
      uint32_t k = *(uint32_t *) data;
      k *= CONST_M;
      k ^= k >> 24;
      k *= CONST_M;
      hash *= CONST_M;
      hash ^= k;
      data += 4;
      len -= 4;
    }

  // Handle the last few bytes of the input array.
  switch(len)
    {
    case 3:
      hash ^= static_cast<unsigned char> (data[2]) << 16;
    case 2:
      hash ^= static_cast<unsigned char> (data[1]) << 8;
    case 1:
      hash ^= static_cast<unsigned char> (data[0]);
      hash *= CONST_M;
    };

  // Do a few final mixes of the hash.
  hash ^= hash >> 13;
  hash *= CONST_M;
  hash ^= hash >> 15;

  return hash;
}

inline uint32_t FNV(string sStr, int len)
{
  uint32_t hash = 2166136261UL;
  const char* cptr = sStr.c_str();
  for(; len; --len)
    {
      hash ^= (uint32_t) (*cptr++);
      hash *= (uint32_t) (16777619UL);
    }
  return hash;
}

typedef struct
{
  inline bool operator() (const char *x, const char *y) const
  {
    return (::strcmp(x, y) == 0);
  }
} CharKeyEq;


typedef struct
{
  inline bool operator() (string x, string y) const
  {
    return (x.compare(y) == 0);
  }
} StringKeyEq;

typedef struct
{
  inline long operator() (string k) const
  {
    return SuperFastHash(k, k.size());
  }
} SuperFastHashChar;

typedef struct
{
  inline long operator() (string k) const
  {
    return FNV1A_Hash_Jesteress(k, k.size());
  }
} JesteressHashChar;

typedef struct
{
  inline long operator() (string k) const
  {
    return Murmor(k, k.size());
  }
} MurmorChar;

typedef struct
{
  inline long operator() (string k) const
  {
    return FNV(k, k.size());
  }
} FNVChar;

/*
 * Setting one these defines will replace the default hash algorithm 
 * rather than explicitly setting it in the template as above
 */ 
//#define JESTERESS
#if defined(JESTERESS) || defined(MURMUR) || defined(SUPERFAST) || defined(FNV)
namespace std
{
template<>
  struct hash<const char *> : public std::unary_function<const char *, size_t>
  {
    inline size_t operator()(const char* str) const
#ifdef JESTERESS
    {
      const uint32_t PRIME = 709607;
      uint32_t hash32 = 2166136261;

      for (;;)
	{
	  uint32_t dw1 = *(uint32_t *) str;
	  if (DWORD_HAS_ZERO_BYTE(dw1))
	    break;

	  str += 4;
	  //        hash32 = hash32 ^ _lrotl(dw1,5);
	  hash32 = hash32 ^ ((dw1 << 5) | (dw1 >> (sizeof (uint32_t) * 3)));

	  uint32_t dw2 = *(uint32_t *) str;
	  if (DWORD_HAS_ZERO_BYTE(dw2))
	    { // finish dw1 without dw2
	      hash32 *= PRIME;
	      break;
	    }

	  str += 4;

	  hash32 = (hash32 ^ dw2) * PRIME;
	}

      while(*str)
	{
	  hash32 = (hash32 ^ *str) * PRIME;
	  str++;
	}

      return hash32;
    }
#endif
#ifdef SUPERFAST
    {
      uint32_t hash, tmp;
      int rem;
      uint32_t len = ::strlen(str);
      hash = len;
      rem = len & 3;
      len >>= 2;

      /* Main loop */
      for (; len > 0; len--)
	{
	  hash += get16bits(str);
	  tmp = (get16bits(str + 2) << 11) ^ hash;
	  hash = (hash << 16) ^ tmp;
	  str += 2 * sizeof (uint16_t);
	  hash += hash >> 11;
	}

      /* Handle end cases */
      switch(rem)
	{
	case 3: hash += get16bits(str);
	  hash ^= hash << 16;
	  hash ^= ((signed char) str[sizeof (uint16_t)]) << 18;
	  hash += hash >> 11;
	  break;
	case 2: hash += get16bits(str);
	  hash ^= hash << 11;
	  hash += hash >> 17;
	  break;
	case 1: hash += (signed char) *str;
	  hash ^= hash << 10;
	  hash += hash >> 1;
	}

      /* Force "avalanching" of final 127 bits */
      hash ^= hash << 3;
      hash += hash >> 5;
      hash ^= hash << 4;
      hash += hash >> 17;
      hash ^= hash << 25;
      hash += hash >> 6;

      return hash;
    }
#endif
#ifdef MURMUR
    {
      uint32_t len = ::strlen(str);
      uint32_t hash = SEED ^ len;

      // Mix 4 bytes at a time into the hash.
      while(len >= 4)
	{
	  uint32_t k = *(uint32_t *) str;
	  k *= CONST_M;
	  k ^= k >> 24;
	  k *= CONST_M;
	  hash *= CONST_M;
	  hash ^= k;
	  str += 4;
	  len -= 4;
	}

      // Handle the last few bytes of the input array.
      switch(len)
	{
	case 3:
	  hash ^= static_cast<unsigned char> (str[2]) << 16;
	case 2:
	  hash ^= static_cast<unsigned char> (str[1]) << 8;
	case 1:
	  hash ^= static_cast<unsigned char> (str[0]);
	  hash *= CONST_M;
	};

      // Do a few final mixes of the hash.
      hash ^= hash >> 13;
      hash *= CONST_M;
      hash ^= hash >> 15;
      return hash;
    }
#endif
#ifdef FNV
    {
      uint32_t hash = 2166136261UL;
      const char* cptr = str;
      uint32_t len = ::strlen(cptr);
      for (; len; --len)
	{
	  hash ^= (uint32_t) (*cptr++);
	  hash *= (uint32_t) (16777619UL);
	}
      return hash;
    }
#endif
  };
};


// Equality function
namespace std
{
template<>
  struct equal_to<const char *> : std::binary_function<const char *, const char *, bool>
  {
    inline bool operator()(const char *x, const char* y) const
    {
      return (::strcmp(x, y) == 0);
    };
  };
};
#endif

#endif
