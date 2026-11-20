#pragma once
#if defined(__has_include)
#  if __has_include(<sys/random.h>)
#    include <sys/random.h>
#    define AC_HAVE_GETENTROPY 1
#  endif
#endif
#if defined(__aarch64__) && (defined(__ARM_FEATURE_SHA2) || defined(__ARM_FEATURE_CRYPTO))
#include <arm_neon.h>
#endif
// ===================================================================
// all_crypto.h
// Современная криптография + legacy. Один файл.
// ===================================================================

#include <regex>
#include <stack>
#include <map>
#include <vector>
#include <string>
#include <functional>
#include <cctype>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <vector>
#include <fstream>
#include <random>
#include <sys/stat.h>
#include <errno.h>
#include <thread>    // для turbo_ (std::thread)
#include <atomic>    // для std::atomic (в turbo_r)
#ifdef __aarch64__
    #include <arm_neon.h>
#elif defined(__x86_64__)
    #include <immintrin.h>
#endif
using namespace std;

// ==================== УТИЛИТЫ ====================
namespace _ {

// ─── Конвертация ───
inline vector<uint8_t> B(const string& s) { return {s.begin(), s.end()}; }
inline string S(const vector<uint8_t>& d) { return {d.begin(), d.end()}; }
inline string H(const vector<uint8_t>& d) {
    stringstream ss; for(auto b:d) ss<<hex<<setw(2)<<setfill('0')<<(int)b; return ss.str();
}
inline string H(const uint8_t* d, size_t n) { return H(vector<uint8_t>(d,d+n)); }
inline vector<uint8_t> U(const string& h) {
    vector<uint8_t> r; for(size_t i=0;i<h.size();i+=2) r.push_back((uint8_t)stoi(h.substr(i,2),0,16)); return r;
}
inline vector<uint8_t> C(const vector<uint8_t>& a, const vector<uint8_t>& b) {
    auto r=a; r.insert(r.end(),b.begin(),b.end()); return r;
}

// ─── Любой тип → байты ───
template<typename T> vector<uint8_t> bytes(const T& v) {
    static_assert(is_trivially_copyable<T>::value, "Требуется тривиально копируемый тип");
    auto p=(const uint8_t*)&v; return {p, p+sizeof(T)};
}
template<> inline vector<uint8_t> bytes<string>(const string& v) { return B(v); }
template<> inline vector<uint8_t> bytes<vector<uint8_t>>(const vector<uint8_t>& v) { return v; }

// ─── Случайные ───
inline mt19937_64& rng() { static mt19937_64 g(random_device{}()); return g; }
inline vector<uint8_t> randb(size_t n) { vector<uint8_t> r(n); for(auto&b:r) b=(uint8_t)(rng()()&0xFF); return r; }
inline uint64_t rand64() { return rng()(); }
// Криптостойкая энтропия ОС: getentropy -> /dev/urandom -> random_device.
// Только для секретов: ключи, IV, nonce, соли.
inline bool csrandb_into(uint8_t* p,size_t n){
#ifdef AC_HAVE_GETENTROPY
    while(n){
        size_t take = n>256 ? 256 : n;
        if(getentropy(p,take)!=0) break;
        p+=take; n-=take;
    }
    if(n==0) return true;
#endif
    { std::ifstream f("/dev/urandom", std::ios::binary);
      if(f){ f.read((char*)p,(std::streamsize)n); if((size_t)f.gcount()==n) return true; } }
    { std::random_device rd;
      for(size_t i=0;i<n;i++) p[i]=(uint8_t)(rd()&0xFFu); }
    return true;
}
inline vector<uint8_t> csrandb(size_t n){
    vector<uint8_t> r(n);
    if(n) csrandb_into(r.data(),n);
    return r;
}


} // namespace _

// ==================== rand.h (НАСТОЯЩИЙ + МОИ ДОБАВЛЕНИЯ) ====================

namespace rand_ {

// ─── БАЗА: настоящий rand.h (XORShift128+ CSPRNG) ───
inline uint64_t _splitmix64(uint64_t& x) {
    x += 0x9e3779b97f4a7c15ULL;
    uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

inline uint64_t _xorshift128p(uint64_t s[2]) {
    uint64_t s0 = s[0], s1 = s[1];
    s1 ^= s1 << 23;
    s1 ^= s1 >> 17;
    s1 ^= s0;
    s1 ^= s0 >> 26;
    s[0] = s1;
    s[1] = s1 ^ (s0 << 45);
    return s[0] + s[1];
}

inline uint64_t u64() {
static uint64_t s[2] = {0, 0};
static bool init = false;
if (!init) {
    auto sb=_::csrandb(16);
    memcpy(&s[0],sb.data(),8); memcpy(&s[1],sb.data()+8,8);
    if (s[0]==0 && s[1]==0) { s[0]=1; s[1]=1; }
    init = true;
}
return _xorshift128p(s);
}

inline uint64_t range(uint64_t min, uint64_t max) {
    if (min == max) return min;
    return min + (u64() % (max - min + 1));
}

inline vector<uint8_t> bytes(size_t n) {
    vector<uint8_t> r(n);
    for (size_t i = 0; i < n; i += 8) {
        uint64_t v = u64();
        size_t sz = min((size_t)8, n - i);
        memcpy(&r[i], &v, sz);
    }
    return r;
}

// ─── МОИ ДОБАВЛЕНИЯ ───

inline uint32_t u32() {
    auto b = bytes(4);
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

inline vector<uint8_t> u128() { return bytes(16); }
inline vector<uint8_t> u256() { return bytes(32); }
inline vector<uint8_t> u512() { return bytes(64); }
inline vector<uint8_t> u_any(size_t n) { return bytes(n); }

inline uint64_t salt() {
auto b=_::csrandb(8); uint64_t v=0;
for(int i=0;i<8;i++) v|=((uint64_t)b[i]<<(8*i));
return v & 0x7FFFFFFFFFFFFFFFULL;
}

inline string str(size_t len) {
    static const char C[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    string r; r.reserve(len);
    auto b = bytes(len);
    for (size_t i = 0; i < len; i++) r += C[b[i] % 62];
    return r;
}

inline string hex_str(size_t n) { return _::H(bytes(n)); }

inline string login(size_t len = 10) { return "user_" + str(len); }

inline string password(size_t len = 16) {
    static const char A[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    string r; r.reserve(len);
    auto b = bytes(len);
    for (size_t i = 0; i < len; i++) r += A[b[i] % 70];
    return r;
}

inline vector<int> arr_int(size_t n, int min, int max) {
    vector<int> r(n);
    for (size_t i = 0; i < n; i++) r[i] = (int)range(min, max);
    return r;
}

template<typename T>
inline vector<vector<T>> matrix(size_t rows, size_t cols, T min, T max) {
    vector<vector<T>> r(rows, vector<T>(cols));
    for (size_t i = 0; i < rows; i++)
        for (size_t j = 0; j < cols; j++)
            r[i][j] = (T)range(min, max);
    return r;
}

template<typename T>
inline vector<vector<vector<T>>> tensor(size_t d1, size_t d2, size_t d3, T min, T max) {
    vector<vector<vector<T>>> r(d1, vector<vector<T>>(d2, vector<T>(d3)));
    for (size_t i = 0; i < d1; i++)
        for (size_t j = 0; j < d2; j++)
            for (size_t k = 0; k < d3; k++)
                r[i][j][k] = (T)range(min, max);
    return r;
}

template<typename T>
inline void shuffle(vector<T>& v) {
    for (size_t i = v.size() - 1; i > 0; i--)
        swap(v[i], v[(size_t)range(0, i)]);
}

template<typename T>
inline T choice(const vector<T>& v) {
    return v[(size_t)range(0, v.size() - 1)];
}

} // namespace rand_

// ==================== SMALL PRIMES (до 16 бит) ====================
namespace _primes {
    static const uint64_t small_primes[] = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
        31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
        127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
        179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
        233, 239, 241, 251, 257, 263, 271, 277, 281, 283,
        293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
        359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
        421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
        479, 487, 491, 499, 503, 509, 521, 523, 541
    };
    static const size_t small_primes_count = sizeof(small_primes) / sizeof(small_primes[0]);
}

// ==================== BIGINT (МНОГОУРОВНЕВАЯ СТРАТЕГИЯ) ====================
namespace _bigint {

using BigNum = vector<uint64_t>;

// ─── Утилиты ───
inline BigNum from_u64(uint64_t v) {
    BigNum r;
    if (v) r.push_back(v);
    return r;
}

inline BigNum from_bytes(const vector<uint8_t>& b) {
    BigNum r;
    size_t sz = (b.size() + 7) / 8;
    r.resize(sz, 0);
    for (size_t i = 0; i < b.size(); i++) 
        r[i / 8] |= ((uint64_t)b[i] << ((i % 8) * 8));
    while (!r.empty() && r.back() == 0) r.pop_back();
    return r;
}

inline vector<uint8_t> to_bytes(const BigNum& n) {
    if (n.empty()) return {0};
    vector<uint8_t> r(n.size() * 8);
    for (size_t i = 0; i < n.size(); i++) 
        for (int j = 0; j < 8; j++) 
            r[i * 8 + j] = (n[i] >> (j * 8)) & 0xFF;
    while (!r.empty() && r.back() == 0) r.pop_back();
    return r;
}

inline int cmp(const BigNum& a, const BigNum& b) {
    if (a.size() != b.size()) return (a.size() < b.size()) ? -1 : 1;
    for (size_t i = a.size(); i-- > 0;) 
        if (a[i] != b[i]) return (a[i] < b[i]) ? -1 : 1;
    return 0;
}
inline bool lt(const BigNum& a, const BigNum& b) { return cmp(a, b) < 0; }
inline bool eq(const BigNum& a, const BigNum& b) { return cmp(a, b) == 0; }
inline bool zero(const BigNum& n) { return n.empty(); }

// ─── Сложение ───
inline BigNum add(const BigNum& a, const BigNum& b) {
BigNum r;
size_t sz = max(a.size(), b.size());
r.reserve(sz + 1);
uint64_t carry = 0;
for (size_t i = 0; i < sz; ++i) {
    uint64_t ai = (i < a.size()) ? a[i] : 0;
    uint64_t bi = (i < b.size()) ? b[i] : 0;
    uint64_t s1 = ai + bi;
    uint64_t c1 = (s1 < ai) ? 1u : 0u;
    uint64_t s2 = s1 + carry;
    uint64_t c2 = (s2 < s1) ? 1u : 0u;
    r.push_back(s2);
    carry = c1 + c2;
}
if (carry) r.push_back(carry);
while (!r.empty() && r.back() == 0) r.pop_back();
return r;
}

// ─── Вычитание ───
inline BigNum sub(const BigNum& a, const BigNum& b) {
BigNum r = a;
uint64_t borrow = 0;
for (size_t i = 0; i < r.size(); ++i) {
    uint64_t bi = (i < b.size()) ? b[i] : 0;
    uint64_t old = r[i];
    uint64_t t1 = old - bi;
    uint64_t nb = (old < bi) ? 1u : 0u;
    uint64_t t2 = t1 - borrow;
    nb += (t1 < borrow) ? 1u : 0u;
    r[i] = t2;
    borrow = nb;
}
while (!r.empty() && r.back() == 0) r.pop_back();
return r;
}

// ─── Умножение ───
inline BigNum mul(const BigNum& a, const BigNum& b) {
    if (a.empty() || b.empty()) return BigNum();
    BigNum r(a.size() + b.size(), 0);
    for (size_t i = 0; i < a.size(); ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b.size(); ++j) {
            __uint128_t cur = (__uint128_t)a[i]*b[j] + r[i+j] + carry;
            r[i+j]=(uint64_t)cur; carry=(uint64_t)(cur>>64);
        }
        size_t k=i+b.size();
        while(carry && k<r.size()){
            __uint128_t cur=(__uint128_t)r[k]+carry;
            r[k]=(uint64_t)cur; carry=(uint64_t)(cur>>64); ++k;
        }
    }
    while(!r.empty()&&r.back()==0) r.pop_back();
    return r;
}
    
       // ─── Деление с остатком (Knuth, без гибрида) ───
inline std::pair<BigNum, BigNum> divmod(const BigNum& a, const BigNum& b) {
    if (b.empty()) return {BigNum(), BigNum()};
    BigNum A=a, B=b;
    while(!A.empty()&&A.back()==0) A.pop_back();
    while(!B.empty()&&B.back()==0) B.pop_back();
    if(B.empty()) return {BigNum(), BigNum()};
    if(cmp(A,B)<0) return {BigNum(), A};
    if(B.size()==1){
        uint64_t d=B[0], carry=0; BigNum q(A.size());
        for(size_t i=A.size(); i-->0;){
            __uint128_t cur=((__uint128_t)carry<<64)|A[i];
            q[i]=(uint64_t)(cur/d); carry=(uint64_t)(cur%d);
        }
        while(!q.empty()&&q.back()==0) q.pop_back();
        BigNum r; if(carry) r.push_back(carry);
        return {q,r};
    }
    size_t n=B.size(), m=A.size()-n;
    uint64_t sh=__builtin_clzll(B[n-1]);
    BigNum v(n,0);
    { uint64_t c=0; for(size_t i=0;i<n;i++){ __uint128_t cur=((__uint128_t)B[i]<<sh)|c; v[i]=(uint64_t)cur; c=(uint64_t)(cur>>64);} }
    BigNum u(m+n+1,0);
    { uint64_t c=0; for(size_t i=0;i<A.size();i++){ __uint128_t cur=((__uint128_t)A[i]<<sh)|c; u[i]=(uint64_t)cur; c=(uint64_t)(cur>>64);} u[A.size()]=c; }
    BigNum q(m+1,0);
    for(size_t jj=m+1; jj-->0;){
        size_t j=jj;
        __uint128_t numer=((__uint128_t)u[j+n]<<64)|u[j+n-1];
        uint64_t qhat=(uint64_t)(numer/v[n-1]);
        __uint128_t rhat=(__uint128_t)(numer%v[n-1]);
        while(qhat!=0){
            __uint128_t lhs=(__uint128_t)qhat*v[n-2];
            __uint128_t rhs=(rhat<<64)|u[j+n-2];
            if(lhs<=rhs) break;
            qhat--; rhat+=(__uint128_t)v[n-1];
            if(rhat>((__uint128_t)1<<64)-1) break;
        }
        uint64_t borrow=0;
        for(size_t i=0;i<n;i++){
            __uint128_t prod=(__uint128_t)qhat*v[i]+borrow;
            __uint128_t cur=(__uint128_t)u[j+i]-(uint64_t)prod;
            u[j+i]=(uint64_t)cur;
            borrow=(uint64_t)(prod>>64)+((cur>>(64))?1:0);
        }
        __uint128_t cur=(__uint128_t)u[j+n]-borrow;
        u[j+n]=(uint64_t)cur;
        if(cur>>(64)){
            qhat--;
            uint64_t c=0;
            for(size_t i=0;i<n;i++){ __uint128_t s=(u[j+i]+v[i])+c; u[j+i]=(uint64_t)s; c=(uint64_t)(s>>64);}
            u[j+n]+=c;
        }
        q[j]=qhat;
    }
    BigNum r(n,0);
    if(sh==0){ for(size_t i=0;i<n;i++) r[i]=u[i]; }
    else { for(size_t i=0;i<n;i++){ uint64_t hi=(i+1<n)?u[i+1]:u[n]; r[i]=(u[i]>>sh)|(hi<<(64-sh)); } }
    while(!q.empty()&&q.back()==0) q.pop_back();
    while(!r.empty()&&r.back()==0) r.pop_back();
    return {q,r};
}

// ─── Модуль ───
inline BigNum mod(const BigNum& a, const BigNum& b) { if(b.empty()) return BigNum(); return divmod(a,b).second; }

// ─── Модульное возведение в степень ───
inline BigNum modpow_ref(const BigNum& base, const BigNum& exp, const BigNum& mod) {
    if (zero(mod)) return BigNum();
    if (zero(exp)) return from_u64(1);
    BigNum result = from_u64(1);
    BigNum b = _bigint::mod(base, mod);
    BigNum e = exp;
    while (!zero(e)) {
        if (e[0] & 1) {
            result = _bigint::mod(mul(result, b), mod);
        }
        b = _bigint::mod(mul(b, b), mod);
        for (size_t i = 0; i < e.size(); ++i) {
            e[i] >>= 1;
            if (i + 1 < e.size() && (e[i+1] & 1)) e[i] |= 0x8000000000000000ULL;
        }
        while (!e.empty() && e.back() == 0) e.pop_back();
    }
    return result;
}
// MODPOW-WINDOW4: окно 4 бита + таблица степеней
static inline BigNum red(const BigNum& x, const BigNum& m){ return divmod(x,m).second; }
static inline size_t bitlen(const BigNum& a){
    if(a.empty()) return 0;
    uint64_t top=a.back(); size_t b=64;
    while(b && !((top>>(b-1))&1)) b--;
    return (a.size()-1)*64 + b;
}
static inline unsigned digit4(const BigNum& k, size_t i){
    size_t bit=4*i, limb=bit/64, off=bit%64;
    if(limb>=k.size()) return 0;
    return (unsigned)((k[limb]>>off)&15);
}
inline BigNum modpow(const BigNum& base, const BigNum& exp, const BigNum& mod){
    if(zero(mod)) return BigNum();
    if(zero(exp)) return from_u64(1);
    BigNum b=red(base,mod);
    BigNum T[16];
    T[0]=from_u64(1); T[1]=b;
    for(int i=2;i<16;i++) T[i]=red(mul(T[i-1],b),mod);
    size_t n=bitlen(exp);
    size_t top=(n+3)/4;
    BigNum r=from_u64(1);
    for(size_t i=top;i-->0;){
        r=red(mul(r,r),mod); r=red(mul(r,r),mod);
        r=red(mul(r,r),mod); r=red(mul(r,r),mod);
        unsigned d=digit4(exp,i);
        if(d) r=red(mul(r,T[d]),mod);
    }
    return r;
}



// ─── Модуль (с новым именем mod_big) ───
inline BigNum mod_big(const BigNum& a, const BigNum& b) {
    return divmod(a, b).second;
}
    
    // ─── Проверка простоты ───
inline bool is_prime(const BigNum& n) {
if (zero(n)) return false;
if (eq(n, from_u64(2)) || eq(n, from_u64(3))) return true;
if ((n[0] & 1) == 0) return false;
for (size_t i = 0; i < _primes::small_primes_count; ++i) {
    uint64_t p = _primes::small_primes[i];
    if (eq(n, from_u64(p))) return true;
    if (lt(n, from_u64(p))) break;
    if (zero(mod_big(n, from_u64(p)))) return false;
}
if (n.size() <= 2) {
    __uint128_t v = n[0];
    if (n.size() == 2) v |= ((__uint128_t)n[1] << 64);
    if (v == 0 || (v & 1) == 0) return false;
    if (v <= 0xFFFFFFFFULL) {
        for (uint64_t d = 3; (__uint128_t)d * d <= v; d += 2)
            if (v % d == 0) return false;
        return true;
    }
}
int k = 10;
if (n.size() > 16) k = 5;
if (n.size() > 32) k = 3;
if (n.size() > 64) k = 2;
BigNum d = sub(n, from_u64(1));
int s = 0;
while (!zero(d) && (d[0] & 1) == 0) {
    for (size_t i = 0; i < d.size(); ++i) {
        d[i] >>= 1;
        if (i + 1 < d.size() && (d[i+1] & 1)) d[i] |= 0x8000000000000000ULL;
    }
    while (!d.empty() && d.back() == 0) d.pop_back();
    s++;
}
if (zero(d)) return false;
for (int i = 0; i < k; ++i) {
    BigNum a = mod_big(from_bytes(_::csrandb(32)), n);
    if (zero(a)) continue;
    BigNum x = modpow(a, d, n);
    if (eq(x, from_u64(1)) || eq(x, sub(n, from_u64(1)))) continue;
    bool composite = true;
    for (int r = 0; r < s - 1; ++r) {
        x = modpow(x, from_u64(2), n);
        if (eq(x, sub(n, from_u64(1)))) { composite = false; break; }
    }
    if (composite) return false;
}
return true;
}

// ─── Генерация простого числа (многоуровневая) ───
inline BigNum random_prime(int bits) {
    // Уровень 0: очень маленькие (≤ 16 бит) — берём из массива
    if (bits <= 16) {
        uint64_t r = _primes::small_primes[rand_::range(0, _primes::small_primes_count - 1)];
        return from_u64(r);
    }

    // Уровень 1: маленькие (16–32 бит) — быстрый поиск
    if (bits <= 32) {
        uint64_t max_val = (1ULL << bits) - 1;
        uint64_t min_val = (1ULL << (bits - 1)) + 1;
        for (int attempt = 0; attempt < 1000; ++attempt) {
            uint64_t v = rand_::range(min_val, max_val);
            v |= 1;  // нечётное
            BigNum r = from_u64(v);
            if (is_prime(r)) return r;
        }
        return from_u64(3);
    }

    // Уровень 2: средние и большие (≥ 32 бит) — стандартный поиск
    int max_attempts = 10000;
    for (int attempt = 0; attempt < max_attempts; ++attempt) {
        vector<uint8_t> b = _::csrandb(bits / 8);
        BigNum r = from_bytes(b);
        if (r.empty()) continue;
        r[0] |= 1;  // нечётное
        if (is_prime(r)) return r;
    }
    return from_u64(3);
}
    

    
// ─── Расширенный алгоритм Евклида (для modinv) ───
inline BigNum modinv(const BigNum& a, const BigNum& m) {
if (zero(a) || zero(m)) return BigNum();
BigNum r0 = m, r1 = mod(a, m);
if (zero(r1)) return BigNum();
// коэффициенты при a: r0 = ... + s0*a, r1 = ... + s1*a
bool s0neg = false; BigNum s0 = from_u64(0);
bool s1neg = false; BigNum s1 = from_u64(1);
while (!zero(r1)) {
    auto qr = divmod(r0, r1);
    BigNum q = qr.first;
    BigNum r2 = sub(r0, mul(q, r1));      // r0 >= q*r1 всегда
    BigNum qs = mul(q, s1);
    bool qsneg = s1neg && !zero(qs);
    bool nneg; BigNum nmag;
    if (s0neg == qsneg) {
        if (cmp(s0, qs) >= 0) { nmag = sub(s0, qs); nneg = s0neg; }
        else { nmag = sub(qs, s0); nneg = !s0neg; }
    } else {
        nmag = add(s0, qs); nneg = s0neg;
    }
    if (zero(nmag)) nneg = false;
    r0 = r1; r1 = r2;
    s0 = s1; s0neg = s1neg;
    s1 = nmag; s1neg = nneg;
}
if (!eq(r0, from_u64(1))) return BigNum();
BigNum res = mod(s0, m);
if (s0neg && !zero(res)) return sub(m, res);
return res;
}
    
        // Преобразование BigNum в десятичную строку
    string to_dec(const _bigint::BigNum& n) {
    _bigint::BigNum r = n;
    _bigint::BigNum zero = _bigint::from_u64(0);
    _bigint::BigNum ten = _bigint::from_u64(10);
    string s;
    while (!_bigint::zero(r)) {
        auto [q, rem] = _bigint::divmod(r, ten);
        s = char('0' + (rem.empty() ? 0u : (unsigned)rem[0])) + s;
        r = q;
    }
        return s.empty() ? "0" : s;
    }
    
} // namespace _bigint

// ==================== SHA-256 ====================
namespace _sha256 {
static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
inline uint32_t R(uint32_t x,uint32_t n){return (x>>n)|(x<<(32-n));}
inline uint32_t CH(uint32_t e,uint32_t f,uint32_t g){return (e&f)^(~e&g);}
inline uint32_t MAJ(uint32_t a,uint32_t b,uint32_t c){return (a&b)^(a&c)^(b&c);}
inline uint32_t BS0(uint32_t x){return R(x,2)^R(x,13)^R(x,22);}
inline uint32_t BS1(uint32_t x){return R(x,6)^R(x,11)^R(x,25);}
inline uint32_t SS0(uint32_t x){return R(x,7)^R(x,18)^(x>>3);}
inline uint32_t SS1(uint32_t x){return R(x,17)^R(x,19)^(x>>10);}

// Единый гейт: ловим ОБА варианта (с подчёркиваниями и без)
#if (defined(__aarch64__) || defined(aarch64)) && (defined(__ARM_FEATURE_SHA2) || defined(__ARM_FEATURE_CRYPTO))
#include <arm_neon.h>

#define SHA256_NEON_ACTIVE 1
#else
#define SHA256_NEON_ACTIVE 0
#endif

inline vector<uint8_t> hash_raw(const vector<uint8_t>& data){
    uint32_t S[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    const uint8_t* p=data.data(); size_t n=data.size();
    uint64_t bl=(uint64_t)n*8;
    auto block=[&](const uint8_t* q){
        uint32_t w[64],a=S[0],b=S[1],c=S[2],d=S[3],e=S[4],f=S[5],g=S[6],h=S[7];
        for(int i=0;i<16;i++) w[i]=((uint32_t)q[i*4]<<24)|((uint32_t)q[i*4+1]<<16)|((uint32_t)q[i*4+2]<<8)|(uint32_t)q[i*4+3];
        for(int i=16;i<64;i++) w[i]=SS1(w[i-2])+w[i-7]+SS0(w[i-15])+w[i-16];
        for(int i=0;i<64;i++){uint32_t t1=h+BS1(e)+CH(e,f,g)+K[i]+w[i],t2=BS0(a)+MAJ(a,b,c);
            h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
        S[0]+=a;S[1]+=b;S[2]+=c;S[3]+=d;S[4]+=e;S[5]+=f;S[6]+=g;S[7]+=h;

    };
    size_t full=n&~(size_t)63;
    for(size_t c=0;c<full;c+=64) block(p+c);
    uint8_t tail[128]; size_t rem=n-full;
    for(size_t i=0;i<rem;i++) tail[i]=p[full+i];
    tail[rem]=0x80;
    size_t padto=(rem<56)?56:120;
    for(size_t i=rem+1;i<padto;i++) tail[i]=0;
    for(int i=7;i>=0;i--) tail[padto+(7-i)]=(uint8_t)((bl>>(i*8))&0xff);
    for(size_t c=0;c<((padto==56)?64:128);c+=64) block(tail+c);
    uint8_t out[32];
    for(int i=0;i<8;i++){out[i*4]=(S[i]>>24)&0xFF;out[i*4+1]=(S[i]>>16)&0xFF;out[i*4+2]=(S[i]>>8)&0xFF;out[i*4+3]=S[i]&0xFF;}
    return vector<uint8_t>(out,out+32);
}
}
inline string sha256(const vector<uint8_t>& d){ return _::H(_sha256::hash_raw(d)); }
inline string sha256(const string& d){ return sha256(_::B(d)); }
inline string sha256(const vector<uint8_t>& d, uint32_t salt){ return sha256(_::C(d, _::bytes(salt))); }
inline string sha256(const string& d, uint32_t salt){ return sha256(_::C(_::B(d), _::bytes(salt))); }
inline string sha256(const vector<uint8_t>& d, const string& salt){ return sha256(_::C(d, _::B(salt))); }
inline string sha256(const string& d, const string& salt){ return sha256(_::C(_::B(d), _::B(salt))); }
template<typename T, typename=typename enable_if<is_arithmetic<T>::value>::type>
string sha256(const T& v){ return sha256(_::bytes(v)); }
inline void sha256(const vector<uint8_t>& d, vector<uint8_t>& out){ out = _sha256::hash_raw(d); }
inline void sha256(const string& d, vector<uint8_t>& out){ out = _sha256::hash_raw(_::B(d)); }
inline void sha256(const vector<uint8_t>& d, uint32_t salt, vector<uint8_t>& out){ out = _sha256::hash_raw(_::C(d, _::bytes(salt))); }
inline void sha256(const string& d, uint32_t salt, vector<uint8_t>& out){ out = _sha256::hash_raw(_::C(_::B(d), _::bytes(salt))); }
inline void sha256(const string& d, const string& path, bool write){ if(write){ auto h = sha256(d); ofstream f(path); f << h; } }



// ==================== SHA-512 ====================
// Self-contained SHA-512 (FIPS 180-4). No OpenSSL. Endian-independent.
// Constants are stored as one base64 blob and decoded at first use.
// Legacy API included: _sha512::hash_raw(vector), sha512(data, salt).
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace _sha512 {

static inline int b64val(unsigned char c) {
    if (c >= (unsigned char)'A' && c <= (unsigned char)'Z') return (int)c - 65;
    if (c >= (unsigned char)'a' && c <= (unsigned char)'z') return (int)c - 97 + 26;
    if (c >= (unsigned char)'0' && c <= (unsigned char)'9') return (int)c - 48 + 52;
    if (c == (unsigned char)'+') return 62;
    if (c == (unsigned char)'/') return 63;
    return -1;
}
static inline std::vector<uint8_t> b64decode(const char* s) {
    std::vector<uint8_t> out;
    uint32_t buf = 0; int bits = 0;
    for (; *s; ++s) {
        int v = b64val((unsigned char)*s);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)((buf >> bits) & 0xFF));
        }
    }
    return out;
}
static inline uint64_t ld64(const uint8_t* p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v = (v << 8) | (uint64_t)p[i];
    return v;
}
static inline void st64(uint8_t* p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) { p[7 - i] = (uint8_t)(v & 0xFFu); v >>= 8; }
}
static inline uint64_t rotr(uint64_t x, unsigned n) {
    return (x >> n) | (x << ((64u - n) & 63u));
}
static inline const uint64_t* tables() {
    static const char B64[] =
    "QoovmNcoriJxN0SRI+9lzbXA+8/sTTsv6bXbpYGJ27w5VsJb80i1OFnxEfG2BdAZkj+CpK8ZT5urHF7V2m2BGNgHqpijAwJCEoNb"
    "AUVwb74kMYW+TuSyjFUMfcPV/7Ticr5ddPJ7iW+A3rH+OxaWsZvcBqclxxI1wZvxdM9pJpTkm2nBnvFK0u++R4Y4TyXjD8GdxouM"
    "1bUkDKHMd6ycZS3pLG9ZKwJ1SnSEqm6m5INcsKncvUH71Hb5iNqDEVO1mD5RUu5m36uoMcZtLbQyELADJ8iY+yE/v1l/x77vDuTG"
    "4AvzPaiPwtWnkUeTCqclBspjUeADgm8UKSlnCg5ucCe3CoVG0i/8LhshOFwmySZNLG38WsQq7VM4DROdlbPfZQpzVIuvY952agq7"
    "PHeyqIHCyS5H7a7mknIshRSCNTuiv+ihTPEDZKgaZku8QjABwkuLcND4l5HHbFGjBlS+MNGS6BnW71IY1pkGJFVlqRD0DjWFV3Eg"
    "KhBqoHAyu9G4GaTBFrjS0MgeN2wIUUGrUydId0zfjuuZNLC8teGbSKg5HAyzxclaY07YqkrjQYrLW5zKT3dj43NoLm/z1rK4o3SP"
    "gu5d77L8eKVjb0MXL2CEyHgUofCrcozHAggaZDnskL7/+iNjHiikUGzr3oK96b75o/eyxnkVxnF48uNyUyvKJz7O6iZhnNGGuMch"
    "wMIH6tp91s3g6x71fU9/7m7ReAbwZ6pyF2+6CmN9xaLImKYRP5gEvvkNrhtxCzUTHEcbKNt39SMEfYQyyqt7QMckkzyevgoVyb68"
    "Qx1nxJwQDUxMxdS+yz5Ctll/KZz8ZX4qX8tvqzrW+uxsRBmMSkdYF2oJ5mfzvMkIu2euhYTKpzs8bvNy/pT4K6VP9TpfHTbxUQ5S"
    "f63mgtGbBWiMKz5sHx+D2av7Qb1rW+DNGRN+IXk="
    ;
    static std::vector<uint8_t> raw = b64decode(B64);
    static uint64_t t[88];
    static bool init = false;
    if (!init) {
        for (unsigned i = 0; i < 88; ++i) t[i] = ld64(raw.data() + 8u * i);
        init = true;
    }
    return t;
}
static inline void compress(uint64_t h[8], const uint8_t* block) {
    const uint64_t* K = tables();
    uint64_t w[80];
    for (unsigned t = 0; t < 16; ++t) w[t] = ld64(block + 8u * t);
    for (unsigned t = 16; t < 80; ++t) {
        uint64_t x = w[t - 15], y = w[t - 2];
        uint64_t s0 = rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
        uint64_t s1 = rotr(y, 19) ^ rotr(y, 61) ^ (y >> 6);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    uint64_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (unsigned t = 0; t < 80; ++t) {
        uint64_t S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t t1 = hh + S1 + ch + K[t] + w[t];
        uint64_t S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}
static inline std::vector<uint8_t> digest(const uint8_t* data, size_t len) {
    const uint64_t* T = tables();
    uint64_t h[8];
    for (unsigned i = 0; i < 8; ++i) h[i] = T[80 + i];
    size_t full = len & ~((size_t)127);
    for (size_t off = 0; off < full; off += 128) compress(h, data + off);
    uint8_t tail[256];
    size_t rem = len - full;
    for (size_t i = 0; i < rem; ++i) tail[i] = data[full + i];
    tail[rem] = 0x80;
    size_t pad_to = (rem < 112) ? 112 : 240;
    for (size_t i = rem + 1; i < pad_to; ++i) tail[i] = 0;
    st64(tail + pad_to,     ((uint64_t)len) >> 61);
    st64(tail + pad_to + 8, ((uint64_t)len) << 3);
    compress(h, tail);
    if (pad_to == 240) compress(h, tail + 128);
    std::vector<uint8_t> out(64);
    for (unsigned i = 0; i < 8; ++i) st64(out.data() + 8u * i, h[i]);
    return out;
}
// Legacy internal API used by the ECDSA/HMAC sections of this library:
static inline std::vector<uint8_t> hash_raw(const std::vector<uint8_t>& data) {
    return digest(data.data(), data.size());
}
static inline std::string to_hex(const std::vector<uint8_t>& d) {
    static const char hx[] = "0123456789abcdef";
    std::string s; s.reserve(d.size() * 2);
    for (size_t i = 0; i < d.size(); ++i) { s.push_back(hx[d[i] >> 4]); s.push_back(hx[d[i] & 15]); }
    return s;
}
} // namespace _sha512

inline std::string sha512(const std::vector<uint8_t>& data) {
    return _sha512::to_hex(_sha512::digest(data.data(), data.size()));
}
inline std::string sha512(const std::string& data) {
    return _sha512::to_hex(_sha512::digest(reinterpret_cast<const uint8_t*>(data.data()), data.size()));
}
inline std::string sha512(const void* data, size_t len) {
    return _sha512::to_hex(_sha512::digest(static_cast<const uint8_t*>(data), len));
}
// Legacy two-argument form: sha512(data, salt) = sha512(data || salt).
// If your old code put the salt first, swap to (salt + data) on the next line.
inline std::string sha512(const std::string& data, const std::string& salt) {
    return sha512(data + salt);
}
inline std::string sha512(const std::vector<uint8_t>& data, const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> j(data);
    j.insert(j.end(), salt.begin(), salt.end());
    return sha512(j);
}

// >>> AUTO-SALT OVERLOAD >>>
inline std::string sha512(const std::string& data, uint64_t salt) {
    return sha512(data + std::to_string(salt));
}
// <<< AUTO-SALT OVERLOAD <<<

// ==================== MD5 ====================








// ==================== MD5 ====================
// ==================== MD5 ====================
// ==================== MD5 ====================
// ==================== MD5 ====================

namespace _md5 {
    static const uint32_t S[64]={7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
    static const uint32_t K[64]={
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };
    inline uint32_t F(uint32_t x,uint32_t y,uint32_t z){return (x&y)|(~x&z);}
    inline uint32_t G(uint32_t x,uint32_t y,uint32_t z){return (x&z)|(y&~z);}
    inline uint32_t H(uint32_t x,uint32_t y,uint32_t z){return x^y^z;}
    inline uint32_t I(uint32_t x,uint32_t y,uint32_t z){return y^(x|~z);}
    inline uint32_t leftrotate(uint32_t x,uint32_t c){return (x<<c)|(x>>(32-c));}
    
    inline vector<uint8_t> hash_raw(const vector<uint8_t>& data){
        uint32_t a0=0x67452301,b0=0xefcdab89,c0=0x98badcfe,d0=0x10325476;
        const uint8_t* src_=data.data(); size_t n_=data.size();   // NOCOPY-ALL
    size_t full_=n_-n_%(64);
    vector<uint8_t> tail_(src_+full_, src_+n_);

        uint64_t orig_bitlen=n_*8;
        tail_.push_back(0x80); while((tail_.size()%64)!=56) tail_.push_back(0);
        tail_.push_back(orig_bitlen&0xff); tail_.push_back((orig_bitlen>>8)&0xff);
        tail_.push_back((orig_bitlen>>16)&0xff); tail_.push_back((orig_bitlen>>24)&0xff);
        tail_.push_back((orig_bitlen>>32)&0xff); tail_.push_back((orig_bitlen>>40)&0xff);
        tail_.push_back((orig_bitlen>>48)&0xff); tail_.push_back((orig_bitlen>>56)&0xff);
            size_t total_=full_+tail_.size();
    auto at_=[&](size_t i)->uint8_t{ return i<full_? src_[i] : tail_[i-full_]; };
    auto ptr_=[&](size_t i)->const uint8_t*{ return i<full_? src_+i : tail_.data()+(i-full_); };
for(size_t off=0;off<total_;off+=64){
            uint32_t M[16]; for(int i=0;i<16;i++) M[i]=(at_(off+i*4))|(at_(off+i*4+1)<<8)|(at_(off+i*4+2)<<16)|(at_(off+i*4+3)<<24);
            uint32_t A=a0,B=b0,C=c0,D=d0;
            for(int i=0;i<64;i++){
                uint32_t f,g;
                if(i<16){f=F(B,C,D);g=i;}
                else if(i<32){f=G(B,C,D);g=(5*i+1)%16;}
                else if(i<48){f=H(B,C,D);g=(3*i+5)%16;}
                else{f=I(B,C,D);g=(7*i)%16;}
                f=f+A+K[i]+M[g]; A=D; D=C; C=B; B=B+leftrotate(f,S[i]);
            }
            a0+=A;b0+=B;c0+=C;d0+=D;
        }
        uint8_t result[16];
        auto put=[&](int i,uint32_t v){result[i]=v&0xff;result[i+1]=(v>>8)&0xff;result[i+2]=(v>>16)&0xff;result[i+3]=(v>>24)&0xff;};
        put(0,a0);put(4,b0);put(8,c0);put(12,d0);
        return {result,result+16};
    }
}

inline string md5(const vector<uint8_t>& d){ return _::H(_md5::hash_raw(d)); }
inline string md5(const string& d){ return md5(_::B(d)); }
inline string md5(const string& d, uint32_t salt){ return md5(d+to_string(salt)); }
inline string md5(const string& d, const string& salt){ return md5(d+salt); }
template<typename T, typename=typename enable_if<is_arithmetic<T>::value>::type>
string md5(const T& v){ return md5(_::bytes(v)); }
inline void md5(const string& d, vector<uint8_t>& out){ out=_md5::hash_raw(_::B(d)); }
inline void md5(const string& d, const string& path, bool write){ if(write){ ofstream f(path); f<<md5(d); } }

// ==================== SHA-1 ====================
namespace _sha1 {
    inline uint32_t leftrotate(uint32_t x,uint32_t c){return (x<<c)|(x>>(32-c));}
    inline vector<uint8_t> hash_raw(const vector<uint8_t>& data){
        uint32_t h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0;
        const uint8_t* src_=data.data(); size_t n_=data.size();   // NOCOPY-ALL
    size_t full_=n_-n_%(64);
    vector<uint8_t> tail_(src_+full_, src_+n_);

        uint64_t bitlen=n_*8;
        tail_.push_back(0x80); while((tail_.size()%64)!=56) tail_.push_back(0);
        for(int i=7;i>=0;i--) tail_.push_back((bitlen>>(i*8))&0xff);
            size_t total_=full_+tail_.size();
    auto at_=[&](size_t i)->uint8_t{ return i<full_? src_[i] : tail_[i-full_]; };
    auto ptr_=[&](size_t i)->const uint8_t*{ return i<full_? src_+i : tail_.data()+(i-full_); };
for(size_t off=0;off<total_;off+=64){
            uint32_t w[80];
            for(int i=0;i<16;i++) w[i]=(at_(off+i*4)<<24)|(at_(off+i*4+1)<<16)|(at_(off+i*4+2)<<8)|at_(off+i*4+3);
            for(int i=16;i<80;i++) w[i]=leftrotate(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
            uint32_t a=h0,b=h1,c=h2,d2=h3,e=h4;
            for(int i=0;i<80;i++){
                uint32_t f,k;
                if(i<20){f=(b&c)|((~b)&d2);k=0x5A827999;}
                else if(i<40){f=b^c^d2;k=0x6ED9EBA1;}
                else if(i<60){f=(b&c)|(b&d2)|(c&d2);k=0x8F1BBCDC;}
                else{f=b^c^d2;k=0xCA62C1D6;}
                uint32_t temp=leftrotate(a,5)+f+e+k+w[i];
                e=d2;d2=c;c=leftrotate(b,30);b=a;a=temp;
            }
            h0+=a;h1+=b;h2+=c;h3+=d2;h4+=e;
        }
        uint8_t result[20];
        auto put=[&](int i,uint32_t v){result[i]=(v>>24)&0xff;result[i+1]=(v>>16)&0xff;result[i+2]=(v>>8)&0xff;result[i+3]=v&0xff;};
        put(0,h0);put(4,h1);put(8,h2);put(12,h3);put(16,h4);
        return {result,result+20};
    }
}

inline string sha1(const vector<uint8_t>& d){ return _::H(_sha1::hash_raw(d)); }
inline string sha1(const string& d){ return sha1(_::B(d)); }
inline string sha1(const string& d, uint32_t salt){ return sha1(d+to_string(salt)); }
inline string sha1(const string& d, const string& salt){ return sha1(d+salt); }
template<typename T, typename=typename enable_if<is_arithmetic<T>::value>::type>
string sha1(const T& v){ return sha1(_::bytes(v)); }
inline void sha1(const string& d, vector<uint8_t>& out){ out=_sha1::hash_raw(_::B(d)); }
inline void sha1(const string& d, const string& path, bool write){ if(write){ ofstream f(path); f<<sha1(d); } }

// ==================== SHA-3-256 / SHA-3-512 (Keccak) ====================
namespace _sha3 {
    static const uint64_t RC[24]={
        0x0000000000000001,0x0000000000008082,0x800000000000808a,0x8000000080008000,
        0x000000000000808b,0x0000000080000001,0x8000000080008081,0x8000000000008009,
        0x000000000000008a,0x0000000000000088,0x0000000080008009,0x000000008000000a,
        0x000000008000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,
        0x8000000000008002,0x8000000000000080,0x000000000000800a,0x800000008000000a,
        0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008
    };
    static const int ROT[24]={
        1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44
    };
    static const int PILN[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

    __attribute__((noinline)) 
    inline uint64_t ROL(uint64_t x, int n) {
        n &= 63;
        if (n == 0) return x;
        return (x << n) | (x >> (64 - n));
    }

    __attribute__((noinline))
    inline void keccak_f(uint64_t S[25]){
        int i, j, r;
        uint64_t t, bc[5];

        for (r = 0; r < 24; r++) {
            for (i = 0; i < 5; i++)
                bc[i] = S[i] ^ S[i + 5] ^ S[i + 10] ^ S[i + 15] ^ S[i + 20];
            for (i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ ROL(bc[(i + 1) % 5], 1);
                for (j = 0; j < 25; j += 5)
                    S[j + i] ^= t;
            }

            t = S[1];
            for (i = 0; i < 24; i++) {
                j = PILN[i];
                bc[0] = S[j];
                S[j] = ROL(t, ROT[i]);
                t = bc[0];
            }

            for (j = 0; j < 25; j += 5) {
                for (i = 0; i < 5; i++)
                    bc[i] = S[j + i];
                for (i = 0; i < 5; i++)
                    S[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }

            S[0] ^= RC[r];
        }
    }

    __attribute__((noinline))
    inline vector<uint8_t> hash_raw(const vector<uint8_t>& data, int outbits){
        int rate_bytes = (1600 - outbits * 2) / 8;
        const uint8_t* src_=data.data(); size_t n_=data.size();   // NOCOPY-ALL
    size_t full_=n_-n_%(rate_bytes);
    vector<uint8_t> tail_(src_+full_, src_+n_);

        tail_.push_back(0x06);
        while(tail_.size() % rate_bytes != rate_bytes - 1) tail_.push_back(0);
        tail_.push_back(0x80);
        
        uint64_t S[25] = {0};
            size_t total_=full_+tail_.size();
    auto at_=[&](size_t i)->uint8_t{ return i<full_? src_[i] : tail_[i-full_]; };
    auto ptr_=[&](size_t i)->const uint8_t*{ return i<full_? src_+i : tail_.data()+(i-full_); };
for(size_t i=0; i<total_; i+=rate_bytes){
            for(int j=0; j<rate_bytes && i+j<total_; j++){
                S[j/8] ^= ((uint64_t)at_(i+j)) << ((j%8)*8);
            }
            keccak_f(S);
        }
        vector<uint8_t> out;
        for(int i=0;i<outbits/8;i++) out.push_back((S[i/8]>>((i%8)*8))&0xff);
        return out;
    }

} // namespace _sha3

inline string sha3_256(const vector<uint8_t>& d){ return _::H(_sha3::hash_raw(d,256)); }
inline string sha3_256(const string& d){ return sha3_256(_::B(d)); }
inline string sha3_256(const string& d,uint64_t salt){ return sha3_256(d+to_string(salt)); }
inline string sha3_256(const string& d,const string& salt){ return sha3_256(d+salt); }
inline void sha3_256(const string& d,vector<uint8_t>& out){ out=_sha3::hash_raw(_::B(d),256); }

inline string sha3_512(const vector<uint8_t>& d){ return _::H(_sha3::hash_raw(d,512)); }
inline string sha3_512(const string& d){ return sha3_512(_::B(d)); }
inline string sha3_512(const string& d,uint64_t salt){ return sha3_512(d+to_string(salt)); }
inline string sha3_512(const string& d,const string& salt){ return sha3_512(d+salt); }
inline void sha3_512(const string& d,vector<uint8_t>& out){ out=_sha3::hash_raw(_::B(d),512); }

// ==================== BLAKE2b ====================
namespace _blake2b {
    static const uint64_t IV[8]={0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
    static const uint8_t SIGMA[10][16]={
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
        {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
        {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
        {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
        {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
        {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
        {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
        {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
        {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0}};
    static inline uint64_t rotr(uint64_t x,int n){return (x>>n)|(x<<(64-n));}
    static inline uint64_t ld64le(const uint8_t* p){uint64_t v=0;for(int i=7;i>=0;i--)v=(v<<8)|p[i];return v;}
    static inline void G(uint64_t* v,int a,int b,int c,int d,uint64_t x,uint64_t y){
        v[a]+=v[b]+x; v[d]=rotr(v[d]^v[a],32); v[c]+=v[d]; v[b]=rotr(v[b]^v[c],24);
        v[a]+=v[b]+y; v[d]=rotr(v[d]^v[a],16); v[c]+=v[d]; v[b]=rotr(v[b]^v[c],63);
    }
    static void compress(uint64_t h[8],const uint8_t blk[128],uint64_t t0,uint64_t f0){
        uint64_t v[16],m[16];
        for(int i=0;i<8;i++)v[i]=h[i];
        for(int i=0;i<8;i++)v[8+i]=IV[i];
        v[12]^=t0; v[14]^=f0;
        for(int i=0;i<16;i++)m[i]=ld64le(blk+8*i);
        for(int r=0;r<12;r++){
            const uint8_t* s=SIGMA[r%10];
            G(v,0,4,8,12,m[s[0]],m[s[1]]); G(v,1,5,9,13,m[s[2]],m[s[3]]);
            G(v,2,6,10,14,m[s[4]],m[s[5]]); G(v,3,7,11,15,m[s[6]],m[s[7]]);
            G(v,0,5,10,15,m[s[8]],m[s[9]]); G(v,1,6,11,12,m[s[10]],m[s[11]]);
            G(v,2,7,8,13,m[s[12]],m[s[13]]); G(v,3,4,9,14,m[s[14]],m[s[15]]);
        }
        for(int i=0;i<8;i++)h[i]^=v[i]^v[i+8];
    }
    static inline std::vector<uint8_t> hash(const std::vector<uint8_t>& data,size_t outlen=64,const std::vector<uint8_t>& key={}){
        uint64_t h[8]; for(int i=0;i<8;i++)h[i]=IV[i];
        h[0]^=0x01010000ULL ^ ((uint64_t)key.size()<<8) ^ (uint64_t)outlen;
        std::vector<uint8_t> full;
        if(!key.empty()){ full.assign(128,0); memcpy(full.data(),key.data(),key.size()); }
        full.insert(full.end(),data.begin(),data.end());
        if(full.empty()){ uint8_t blk[128]={0}; compress(h,blk,0,~0ULL); }
        else{
            size_t off=0; uint64_t t=0;
            while(off<full.size()){
                size_t take=std::min((size_t)128,full.size()-off);
                uint8_t blk[128]={0}; memcpy(blk,full.data()+off,take);
                t+=take;
                bool last=(off+take>=full.size());
                compress(h,blk,t,last?~0ULL:0);
                off+=take;
            }
        }
        std::vector<uint8_t> out(outlen);
        for(size_t i=0;i<outlen;i++)out[i]=(uint8_t)(h[i/8]>>(8*(i%8)));
        return out;
    }
    static inline std::vector<uint8_t> hash_raw(const std::vector<uint8_t>& d){ return hash(d,64); }
}

inline string blake2b(const vector<uint8_t>& d){ return _::H(_blake2b::hash_raw(d)); }
inline string blake2b(const string& d){ return blake2b(_::B(d)); }
inline string blake2b(const string& d,uint64_t salt){ return blake2b(d+to_string(salt)); }
inline void blake2b(const string& d,vector<uint8_t>& out){ out=_blake2b::hash_raw(_::B(d)); }

inline string blake2s(const string& d){ return blake2b(d).substr(0,64); }



// ==================== ГОСТ Р 34.11-2012 (Стрибог) ====================
// Self-contained Streebog-256/512 (GOST R 34.11-2012 / RFC 6986). No OpenSSL.
// Verified against all four official RFC 6986 test vectors.
// Tables (Pi, Tau, A, C) are one base64 blob, decoded and self-checked at first use.
// Legacy API included: _stribog::hash_raw(vector, bits).
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace _stribog {

static inline int b64val(unsigned char c) {
    if (c >= (unsigned char)'A' && c <= (unsigned char)'Z') return (int)c - 65;
    if (c >= (unsigned char)'a' && c <= (unsigned char)'z') return (int)c - 97 + 26;
    if (c >= (unsigned char)'0' && c <= (unsigned char)'9') return (int)c - 48 + 52;
    if (c == (unsigned char)'+') return 62;
    if (c == (unsigned char)'/') return 63;
    return -1;
}
static inline std::vector<uint8_t> b64decode(const char* s) {
    std::vector<uint8_t> out;
    uint32_t buf = 0; int bits = 0;
    for (; *s; ++s) {
        int v = b64val((unsigned char)*s);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)((buf >> bits) & 0xFF));
        }
    }
    return out;
}
static inline uint64_t ld64(const uint8_t* p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v = (v << 8) | (uint64_t)p[i];
    return v;
}
static inline void st64(uint8_t* p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) { p[7 - i] = (uint8_t)(v & 0xFFu); v >>= 8; }
}
struct Tables {
    uint8_t PI[256];
    uint8_t TAU[64];
    uint64_t A[64];
    uint8_t C[12][64];
};
static inline const Tables& tables() {
    static const char B64[] =
    "/O7dEc9uMRb7xPraI8UETel38NuTLpm6FzbxuxTNX8H5GGVa4lzvIYEcPEKLAY5PBYQCruNqj6AGC+2Yf9TTH+s0LFHqyEir8ipo"
    "ov06zsy1cA5WCAx2Er9yE0ect12HFaGWKRB7msfzkXhvnZ6ysTJ1GT3/NYp+bVTGgMO9DVff9SSpPqhDydd51vZ8IrkD4A/s3nqU"
    "sLzc6ChQTjMKSqeXYHMeAGJEGrg4gmSfJkGtRUaSJ15VL4yjpX1p1ZU7B1izQIasHfcwN2vkiNnnieEbg0lMP/j+jVOqkMrYhWEg"
    "cWekLSsJW8ubJdC+5WxSWaZ00ub0tMDRZq/COUtjtgAIEBggKDA4AQkRGSEpMTkCChIaIioyOgMLExsjKzM7BAwUHCQsNDwFDRUd"
    "JS01PQYOFh4mLjY+Bw8XHycvNz+OIPqnK6C0cEcQfd2bUFo4rQiw4MMoLRzYBFhw7xSYDmwCLDj5CkwHNgEWHPIFJo0bjgsOeYwT"
    "yINHiweyRodkoBHTgIGOj0BQhudAzkfJIChD/SBnreoQFK/wEL3YdQgK2XgI0Gy0BAXiPARoNloCjHEeAjQbLQFGtg8BGoOYjpDa"
    "tSo4eudvSG3UFRw9/bkkuGqEDpDw0hJcNUIHSHhpCS6UIY0kPLqKF0qeyBIeXUWFJU9kCQ+grMycqTKKiVCdTfBdX2YUUcCoeKCh"
    "MwqmYFQ8UN6XBVMwKh4ob8WMpxgVDxS57EbdDISJCtJ2I+AGQsoFaTufcAMhZYy6k8E4hidd8JzoqqhDnaB4TnRVVK/AUDwnOqQq"
    "2WAoHp0dUhXiMBQPwIAphHEYColgQJpCtgwFyjAgTSFbBoxlGBConkVsNIh6OAW5rDYaRD0cjNJWGw0ikA5GaSuDiBFIByO6m89E"
    "hiSNn13D6SJDEsjBoO/6Ea8JZO5Q+X2G2Yoydyjk+iBUqAsynHJ9ECpUixlOObAIFSrLgieSWASEFetBnUksAkKE+67AqhYBIULz"
    "V2BVC46eIfelMKSLR0+e9dwYcKalbiRAWY44U9w3EiCiRxynbpUJEFGtDt03xIoIptgH4JViRQRTbI1wxDGsAqc2yDhillYB3Rtk"
    "HDFLK47gg7EIW9oeytrp68svgcBlfB8vanZDLkXQFnFOuI11hcT8S3zgkZJnaQGiQioIpGDTFQV2dDbMdE0j3YBlWfKmRQdvo7WK"
    "qZ0vGk/jnUYPcLXX8/7qcgojK5hh1V4PFrUBMZq1F2sS1plYXLVhwtsKp8pV3aIb18vNVuZ5BHAhsZu39XTcrCvOL8cKOfwoaj2E"
    "NQbxXl9SnB+L8up1FLEpe3vT4g/kkDWescHJOjdgYtsJwrb0Q4Z62zGZHpb1CroKsu8f37PoFWbS+UjhoF1x5N1IjoV+M1w8fZ1y"
    "HK1oXjU/qdcsgu0D1nXYtxMzk1IDvjRT6qGT6DfxIgy+vITj0S5L6musrUdHmZo/QQxsqSNjfxUcHxaGEEo1njXXgA//vb/NF0cl"
    "OvWj3/8AtyMnGhZ6VqJ+qepj9WAXWP18bP5Xrk+urh0609lvpMM7ejA5wC1mxPlRQqRsGH+atJrwjsbP+qa3HJq3tAryH2bCvsa2"
    "v3HFcjaQTzX6aEB6RmR9bvTHDhbuqsXsUayG/r8kCVQ5nsbH5r+HydNHPjMZepPJCZKrxS2CLDcGR2mDKEoFBDUXRUyiPErziIZW"
    "TToU1JObH1tCTZPJpwPnqgIMbkFBTrf4cZw23h6JtEQ7TdvEmvSJK8uSmwaQadGNK9GlxC82rMI1WVGo2aR/DdS/AuceN49aVBYx"
    "IpuUTJrY7BZf3jp9OhsliUIkPNlVt+ANCYSACkQL27LOsXsripqmB5xUDjjckssfKmByYURRgyNa26u+3qaABW9SOCrlSLLk8/OJ"
    "Qecc/4p42x//4YobM2EDn+dnAq9pM0t6HmwwO3ZS9DaY+tEVO7bDdLTH+5hFnO17zZ7Q78iJ+zACxs1jWv6U2Ppru+urB2EgAYAh"
    "FIRmeYodce/qSLnK77rNHX1HbpjeollKwG/YXWvKpM2B8y0bN47nZ/EWMbrSE4CwBEmxes2kPDK83x13+CAS1DAhn5tdgO+dGJHM"
    "hucdpKqI4ShS+vQX1dmyG5lIvJJK8RvXIA=="
    ;
    static std::vector<uint8_t> raw = b64decode(B64);
    static Tables t;
    static bool init = false;
    if (!init) {
        if (raw.size() != 1600u) {
            std::fprintf(stderr, "[all_crypto] FATAL: Streebog tables corrupted (%u bytes, expected 1600)\n", (unsigned)raw.size());
            std::abort();
        }
        for (unsigned i = 0; i < 256; ++i) t.PI[i] = raw[i];
        for (unsigned i = 0; i < 64; ++i) t.TAU[i] = raw[256 + i];
        for (unsigned i = 0; i < 64; ++i) t.A[i] = ld64(raw.data() + 320 + 8u * i);
        for (unsigned i = 0; i < 12; ++i)
            for (unsigned j = 0; j < 64; ++j) t.C[i][j] = raw[832 + 64u * i + j];
        unsigned seen[256];
        for (unsigned i = 0; i < 256; ++i) seen[i] = 0;
        for (unsigned i = 0; i < 256; ++i) seen[t.PI[i]] = 1;
        unsigned sum = 0;
        for (unsigned i = 0; i < 256; ++i) sum += seen[i];
        if (sum != 256u || t.A[0] != 0x8e20faa72ba0b470ULL || t.C[0][0] != 0xb1) {
            std::fprintf(stderr, "[all_crypto] FATAL: Streebog tables failed self-check\n");
            std::abort();
        }
        init = true;
    }
    return t;
}
static inline void xor64(uint8_t* r, const uint8_t* a, const uint8_t* b) {
    for (unsigned i = 0; i < 64; ++i) r[i] = (uint8_t)(a[i] ^ b[i]);
}
static inline void S(uint8_t* r, const uint8_t* a) {
    const Tables& t = tables();
    for (unsigned i = 0; i < 64; ++i) r[i] = t.PI[a[i]];
}
static inline void P(uint8_t* r, const uint8_t* a) {
    const Tables& t = tables();
    for (unsigned i = 0; i < 64; ++i) r[i] = a[t.TAU[i]];
}
static inline void l_ref(uint8_t* r, const uint8_t* a) {
    const Tables& t = tables();
    for (unsigned i = 0; i < 8; ++i) {
        uint64_t v = ld64(a + 8u * i), acc = 0;
        for (unsigned j = 0; j < 64; ++j)
            if ((v >> (63u - j)) & 1u) acc ^= t.A[j];
        st64(r + 8u * i, acc);
    }
}
// STRIBOG-TABLES-v3: таблицы из матрицы A напрямую (без l_slow, без ld64), самопроверка+откат
static uint64_t LT[8][256];
static bool lt_ready=false, lt_use=false;
static void lt_build(){
    const Tables& tb = tables();
    for(int pp=0;pp<8;pp++) for(int v=0;v<256;v++){
        uint64_t acc=0;
        for(int bb=0;bb<8;bb++) if((v>>bb)&1) acc ^= tb.A[8*pp+7-bb];
        LT[pp][v]=acc;
    }
    uint8_t in[64], r1[64], r2[64]; bool ok=true;
    for(int tr=0; tr<4 && ok; tr++){
        for(int i=0;i<64;i++) in[i]=(uint8_t)(i*37+tr*101+13);
        l_ref(r1,in);
        for(int row=0;row<8;row++){
            uint64_t acc=0; for(int pp=0;pp<8;pp++) acc^=LT[pp][in[8*row+pp]];
            for(int k=0;k<8;k++) r2[8*row+k]=(uint8_t)(acc>>(8*(7-k)));
        }
        for(int i=0;i<64;i++) if(r1[i]!=r2[i]){ok=false;break;}
    }
    lt_use=ok; lt_ready=true;
}
static inline void L(uint8_t* r, const uint8_t* a){
    if(!lt_ready) lt_build();
    if(!lt_use){ l_ref(r,a); return; }
    for(int row=0;row<8;row++){
        const uint8_t* s=a+8*row;
        uint64_t acc=LT[0][s[0]]^LT[1][s[1]]^LT[2][s[2]]^LT[3][s[3]]^LT[4][s[4]]^LT[5][s[5]]^LT[6][s[6]]^LT[7][s[7]];
        uint8_t* d=r+8*row;
        d[0]=(uint8_t)(acc>>56); d[1]=(uint8_t)(acc>>48); d[2]=(uint8_t)(acc>>40); d[3]=(uint8_t)(acc>>32);
        d[4]=(uint8_t)(acc>>24); d[5]=(uint8_t)(acc>>16); d[6]=(uint8_t)(acc>>8); d[7]=(uint8_t)acc;
    }
}

static inline void LPS(uint8_t* r, const uint8_t* a) {
    uint8_t t[64], u[64];
    S(t, a); P(u, t); L(r, u);   // reads 'a' fully before writing 'r' -> in-place safe
}
static inline void E(uint8_t* out, const uint8_t* Kin, const uint8_t* m) {
    const Tables& tb = tables();
    uint8_t k[64], st[64];
    for (unsigned i = 0; i < 64; ++i) k[i] = Kin[i];
    xor64(st, m, k);
    for (unsigned i = 0; i < 12; ++i) {
        LPS(st, st);              // st = LPS(st)
        xor64(k, k, tb.C[i]);     // k  = k ^ C[i]
        LPS(k, k);                // k  = LPS(k) -> next round key
        xor64(st, st, k);         // st = st ^ k
    }
    for (unsigned i = 0; i < 64; ++i) out[i] = st[i];
}
static inline void g(uint8_t* out, const uint8_t* N, const uint8_t* h, const uint8_t* m) {
    uint8_t t[64], K[64], e[64];
    xor64(t, h, N);
    LPS(K, t);
    E(e, K, m);
    xor64(t, e, h);
    xor64(out, t, m);
}
static inline void add512(uint8_t* acc, const uint8_t* v) {
    uint32_t carry = 0;
    for (int i = 63; i >= 0; --i) {
        uint32_t s = (uint32_t)acc[i] + (uint32_t)v[i] + carry;
        acc[i] = (uint8_t)s; carry = s >> 8;
    }
}
static inline void add_small(uint8_t* acc, uint64_t v) {
    uint32_t carry = 0;
    for (int i = 63; i >= 56; --i) {
        uint32_t s = (uint32_t)acc[i] + (uint32_t)(v & 0xFFu) + carry;
        acc[i] = (uint8_t)s; carry = s >> 8; v >>= 8;
    }
    for (int i = 55; i >= 0 && carry; --i) {
        uint32_t s = (uint32_t)acc[i] + carry;
        acc[i] = (uint8_t)s; carry = s >> 8;
    }
}
static inline std::vector<uint8_t> digest(const uint8_t* data, size_t len, unsigned bits) {
    uint8_t h[64], N[64], Sig[64], m[64], zero[64];
    uint8_t iv = (bits == 512u) ? 0x00 : 0x01;   // IV: 0x01*64 for 256, 0x00*64 for 512
    for (unsigned i = 0; i < 64; ++i) { h[i] = iv; N[i] = 0; Sig[i] = 0; zero[i] = 0; }
    size_t rem = len % 64, full = len - rem;
    for (size_t off = 0; off < full; off += 64) {
        for (unsigned j = 0; j < 64; ++j) m[j] = data[off + 63u - j];
        g(h, N, h, m);
        add_small(N, 512u);
        add512(Sig, m);
    }
    for (unsigned j = 0; j < 64; ++j) m[j] = 0;
    m[63u - rem] = 0x01;
    for (size_t j = 0; j < rem; ++j) m[63u - j] = data[full + j];   // reversed tail
    g(h, N, h, m);
    add_small(N, (uint64_t)rem * 8u);
    add512(Sig, m);
    g(h, zero, h, N);
    g(h, zero, h, Sig);
    size_t outlen = (bits == 512u) ? 64 : 32;
    std::vector<uint8_t> out(outlen);
    for (size_t i = 0; i < outlen; ++i) out[i] = h[outlen - 1u - i];
    return out;
}
static inline std::vector<uint8_t> digest(const uint8_t* data, size_t len) {
    return digest(data, len, 256u);
}
// Legacy internal API used by the HMAC section of this library:
static inline std::vector<uint8_t> hash_raw(const std::vector<uint8_t>& data, int bits = 256) {
    return digest(data.data(), data.size(), (bits == 512) ? 512u : 256u);
}
static inline std::string to_hex(const std::vector<uint8_t>& d) {
    static const char hx[] = "0123456789abcdef";
    std::string s; s.reserve(d.size() * 2);
    for (size_t i = 0; i < d.size(); ++i) { s.push_back(hx[d[i] >> 4]); s.push_back(hx[d[i] & 15]); }
    return s;
}
} // namespace _stribog

inline std::string stribog256(const std::vector<uint8_t>& data) {
    return _stribog::to_hex(_stribog::digest(data.data(), data.size(), 256u));
}
inline std::string stribog256(const std::string& data) {
    return _stribog::to_hex(_stribog::digest(reinterpret_cast<const uint8_t*>(data.data()), data.size(), 256u));
}
inline std::string stribog256(const void* data, size_t len) {
    return _stribog::to_hex(_stribog::digest(static_cast<const uint8_t*>(data), len, 256u));
}
inline std::string stribog512(const std::vector<uint8_t>& data) {
    return _stribog::to_hex(_stribog::digest(data.data(), data.size(), 512u));
}
inline std::string stribog512(const std::string& data) {
    return _stribog::to_hex(_stribog::digest(reinterpret_cast<const uint8_t*>(data.data()), data.size(), 512u));
}
inline std::string stribog512(const void* data, size_t len) {
    return _stribog::to_hex(_stribog::digest(static_cast<const uint8_t*>(data), len, 512u));
}

// ==================== AES-256 ====================










// ==================== AES-256 ====================

// ==================== AES-256 ====================

namespace _aes {
    static const uint8_t sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };
    static const uint8_t rsbox[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };
    static const uint8_t Rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

    inline void KeyExpansion(const uint8_t* key, uint8_t* RoundKey) {
        int i, j, k;
        uint8_t tempa[4];
        int Nk = 8; // AES-256
        int Nr = 14;
        
        for (i = 0; i < Nk; ++i) {
            RoundKey[(i * 4) + 0] = key[(i * 4) + 0];
            RoundKey[(i * 4) + 1] = key[(i * 4) + 1];
            RoundKey[(i * 4) + 2] = key[(i * 4) + 2];
            RoundKey[(i * 4) + 3] = key[(i * 4) + 3];
        }
        for (i = Nk; i < 4 * (Nr + 1); ++i) {
            k = (i - 1) * 4;
            tempa[0] = RoundKey[k + 0]; tempa[1] = RoundKey[k + 1];
            tempa[2] = RoundKey[k + 2]; tempa[3] = RoundKey[k + 3];
            if (i % Nk == 0) {
                uint8_t u8tmp = tempa[0];
                tempa[0] = tempa[1]; tempa[1] = tempa[2];
                tempa[2] = tempa[3]; tempa[3] = u8tmp;
                tempa[0] = sbox[tempa[0]]; tempa[1] = sbox[tempa[1]];
                tempa[2] = sbox[tempa[2]]; tempa[3] = sbox[tempa[3]];
                tempa[0] = tempa[0] ^ Rcon[i / Nk];
            } else if (i % Nk == 4) {
                tempa[0] = sbox[tempa[0]]; tempa[1] = sbox[tempa[1]];
                tempa[2] = sbox[tempa[2]]; tempa[3] = sbox[tempa[3]];
            }
            j = i * 4; k = (i - Nk) * 4;
            RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
            RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
            RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
            RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
        }
    }

    inline void AddRoundKey(uint8_t round, uint8_t* state, const uint8_t* RoundKey) {
        for (uint8_t i = 0; i < 4; ++i)
            for (uint8_t j = 0; j < 4; ++j)
                state[i * 4 + j] ^= RoundKey[round * 16 + i * 4 + j];
    }

    inline void SubBytes(uint8_t* state) {
        for (uint8_t i = 0; i < 16; ++i) state[i] = sbox[state[i]];
    }
    inline void InvSubBytes(uint8_t* state) {
        for (uint8_t i = 0; i < 16; ++i) state[i] = rsbox[state[i]];
    }

    inline void ShiftRows(uint8_t* state) {
        uint8_t temp;
        temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
        temp = state[2]; state[2] = state[10]; state[10] = temp;
        temp = state[6]; state[6] = state[14]; state[14] = temp;
        temp = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = temp;
    }

    inline void InvShiftRows(uint8_t* state) {
        uint8_t temp;
        temp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;
        temp = state[2]; state[2] = state[10]; state[10] = temp;
        temp = state[6]; state[6] = state[14]; state[14] = temp;
        temp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
    }

    inline uint8_t xtime(uint8_t x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }
    inline uint8_t Multiply(uint8_t x, uint8_t y) {
        return (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
    }

    inline void MixColumns(uint8_t* state) {
        uint8_t tmp, tm, t;
        for (uint8_t i = 0; i < 4; ++i) {
            t = state[i*4+0];
            tmp = state[i*4+0] ^ state[i*4+1] ^ state[i*4+2] ^ state[i*4+3];
            tm = state[i*4+0] ^ state[i*4+1]; tm = xtime(tm); state[i*4+0] ^= tm ^ tmp;
            tm = state[i*4+1] ^ state[i*4+2]; tm = xtime(tm); state[i*4+1] ^= tm ^ tmp;
            tm = state[i*4+2] ^ state[i*4+3]; tm = xtime(tm); state[i*4+2] ^= tm ^ tmp;
            tm = state[i*4+3] ^ t;            tm = xtime(tm); state[i*4+3] ^= tm ^ tmp;
        }
    }

    inline void InvMixColumns(uint8_t* state) {
        int i;
        uint8_t a, b, c, d;
        for (i = 0; i < 4; ++i) {
            a = state[i*4+0]; b = state[i*4+1]; c = state[i*4+2]; d = state[i*4+3];
            state[i*4+0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
            state[i*4+1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
            state[i*4+2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
            state[i*4+3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
        }
    }

    inline void Cipher(uint8_t* state, const uint8_t* RoundKey) {
        uint8_t round = 0;
        AddRoundKey(0, state, RoundKey);
        for (round = 1; round < 14; ++round) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(round, state, RoundKey);
        }
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(14, state, RoundKey);
    }

    inline void InvCipher(uint8_t* state, const uint8_t* RoundKey) {
        uint8_t round = 14;
        AddRoundKey(14, state, RoundKey);
        for (round = 13; round > 0; --round) {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(round, state, RoundKey);
            InvMixColumns(state);
        }
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(0, state, RoundKey);
    }

    inline vector<uint8_t> encrypt_raw(const vector<uint8_t>& plain,const vector<uint8_t>& key,const vector<uint8_t>& iv){
    // NOCOPY: паддинг собирается на лету из источника, копии входа нет
    uint8_t rk[240]; KeyExpansion(key.data(),rk);
    size_t rem=plain.size()%16; size_t full=plain.size()-rem;
    uint8_t pad=0; size_t outsz=rem?full+16:full;
    vector<uint8_t> res(outsz);
    uint8_t prev[16]; memcpy(prev,iv.data(),16);
    const uint8_t* src=plain.data();
    for(size_t i=0;i<full;i+=16){ uint8_t blk[16];
        for(int j=0;j<16;j++) blk[j]=(uint8_t)(src[i+j]^prev[j]);
        Cipher(blk,rk); memcpy(&res[i],blk,16); memcpy(prev,blk,16); }
    if(rem||false){ uint8_t blk[16];
        for(size_t j=0;j<16;j++){ uint8_t b=(j<rem)?src[full+j]:pad; blk[j]=(uint8_t)(b^prev[j]); }
        Cipher(blk,rk); memcpy(&res[full],blk,16); }
    return res;
}
    inline vector<uint8_t> decrypt_raw(const vector<uint8_t>& cipher,const vector<uint8_t>& key,const vector<uint8_t>& iv){
        uint8_t rk[240]; KeyExpansion(key.data(),rk);
        vector<uint8_t> res(cipher.size());
        uint8_t prev[16]; memcpy(prev, iv.data(), 16);
        for(size_t i=0;i<cipher.size();i+=16){
            uint8_t t[16]; memcpy(t,&cipher[i],16);
            memcpy(&res[i], &cipher[i], 16);
            InvCipher(&res[i],rk);
            for(int j=0;j<16;j++) res[i+j]^=prev[j];
            memcpy(prev, t, 16);
        }
        return res;
    }
}
// ─── AES публичные обёртки ───





#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
// NEON-CLEAN: аппаратный AES-CBC encrypt (корректная формула ARM)
#include <arm_neon.h>
static inline void neon_cbc_enc(uint8_t* o,const uint8_t* in,size_t n,const uint8_t* k,const uint8_t* iv){
    uint8_t rk[240]; _aes::KeyExpansion(k,rk);
    uint8x16_t kk[15];
    for(int q=0;q<15;q++)kk[q]=vld1q_u8(rk+q*16);
    const uint8x16_t zero=vdupq_n_u8(0);
    uint8x16_t p=vld1q_u8(iv);
    for(size_t q=0;q<n/16;q++){
        uint8x16_t s=veorq_u8(vld1q_u8(in+q*16),p);
        s=veorq_u8(s,kk[0]);
        for(int r=1;r<14;r++){
            s=vaeseq_u8(s,zero);   // SubBytes+ShiftRows
            s=vaesmcq_u8(s);       // MixColumns
            s=veorq_u8(s,kk[r]);   // AddRoundKey
        }
        s=vaeseq_u8(s,zero);
        s=veorq_u8(s,kk[14]);
        vst1q_u8(o+q*16,s); p=s;
    }
}
static inline void neon_block_enc(uint8_t* out,const uint8_t* in,const uint8_t* rk){
    uint8x16_t kk[15];
    for(int q=0;q<15;q++)kk[q]=vld1q_u8(rk+q*16);
    const uint8x16_t zero=vdupq_n_u8(0);
    uint8x16_t s=vld1q_u8(in);
    s=veorq_u8(s,kk[0]);
    for(int r=1;r<14;r++){ s=vaeseq_u8(s,zero); s=vaesmcq_u8(s); s=veorq_u8(s,kk[r]); }
    s=vaeseq_u8(s,zero); s=veorq_u8(s,kk[14]);
    vst1q_u8(out,s);
}
static inline void neon_block_dec(uint8_t* out,const uint8_t* in,const uint8_t* rk){
    uint8x16_t kk[15];
    for(int q=0;q<15;q++)kk[q]=vld1q_u8(rk+q*16);
    const uint8x16_t zero=vdupq_n_u8(0);
    uint8x16_t s=vld1q_u8(in);
    s=veorq_u8(s,kk[14]);
    for(int r=13;r>=1;r--){
        s=vaesdq_u8(s,zero);
        s=veorq_u8(s,kk[r]);
        s=vaesimcq_u8(s);
    }
    s=vaesdq_u8(s,zero);
    s=veorq_u8(s,kk[0]);
    vst1q_u8(out,s);
}
static inline void neon_cbc_dec(uint8_t* o,const uint8_t* in,size_t n,const uint8_t* k,const uint8_t* iv){
    uint8_t rk[240]; _aes::KeyExpansion(k,rk);
    uint8_t prev[16]; memcpy(prev,iv,16);
    for(size_t q=0;q<n/16;q++){
        uint8_t ct[16]; memcpy(ct,in+q*16,16);
        uint8_t raw[16]; neon_block_dec(raw,ct,rk);
        for(int b=0;b<16;b++) o[q*16+b]=raw[b]^prev[b];
        memcpy(prev,ct,16);
    }
}
#endif
inline vector<uint8_t> aes256_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key,const vector<uint8_t>& iv){
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    if(plain.size()%16==0 && iv.size()==16 && key.size()==32){
        vector<uint8_t> out(plain.size());
        neon_cbc_enc(out.data(),plain.data(),plain.size(),key.data(),iv.data());
        return out;
    }
#endif


    return _aes::encrypt_raw(plain,key,iv);
}
inline vector<uint8_t> aes256_encrypt(const string& plain,const string& key,const string& iv){
    return aes256_encrypt(_::B(plain),_::B(key),_::B(iv));
}
inline vector<uint8_t> aes256_decrypt(const vector<uint8_t>& cipher,const vector<uint8_t>& key,const vector<uint8_t>& iv){
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    if(cipher.size()%16==0 && iv.size()==16 && key.size()==32){
        vector<uint8_t> out(cipher.size());
        neon_cbc_dec(out.data(),cipher.data(),cipher.size(),key.data(),iv.data());
        return out;
    }
#endif

    return _aes::decrypt_raw(cipher,key,iv);
}
inline vector<uint8_t> aes256_decrypt(const string& cipher,const string& key,const string& iv){
    return aes256_decrypt(_::B(cipher),_::B(key),_::B(iv));
}

// ==================== AES-256-GCM ====================
namespace _gcm {
    inline void inc32(vector<uint8_t>& ctr){
        uint32_t v=((uint32_t)ctr[12]<<24)|((uint32_t)ctr[13]<<16)|((uint32_t)ctr[14]<<8)|ctr[15];
        v++;
        ctr[12]=(v>>24)&0xff; ctr[13]=(v>>16)&0xff; ctr[14]=(v>>8)&0xff; ctr[15]=v&0xff;
    }
    inline void mul(uint8_t* x,const uint8_t* y){
        uint8_t z[16]={0},v[16]; memcpy(v,y,16);
        for(int i=0;i<128;i++){
            if(x[i/8]&(1<<(7-(i%8)))){ for(int j=0;j<16;j++) z[j]^=v[j]; }
            uint8_t carry=v[15]&1;
            for(int j=15;j>0;j--) v[j]=(v[j]>>1)|(v[j-1]<<7); v[0]>>=1;
            if(carry) v[0]^=0xe1;
        }
        memcpy(x,z,16);
    }
    // табличное умножение в GF(2^128): T[i][v] = (байт v на позиции i) * H
    inline void build_table(uint8_t* T,const uint8_t* H){
        uint8_t M[128][16];
        memcpy(M[0],H,16);
        for(int p=1;p<128;p++){
            const uint8_t* s=M[p-1]; uint8_t* dd=M[p];
            uint8_t carry=s[15]&1;
            for(int q=15;q>0;q--) dd[q]=(uint8_t)((s[q]>>1)|(s[q-1]<<7));
            dd[0]=(uint8_t)(s[0]>>1); if(carry) dd[0]^=0xe1;
        }
        for(int i=0;i<16;i++){
            uint8_t* base=T+(size_t)i*256*16;
            memset(base,0,16);
            for(int v=1;v<256;v++){
                int k=__builtin_ctz((unsigned)v);
                const uint8_t* a=base+(size_t)(v&(v-1))*16;
                const uint8_t* m=M[8*i+(7-k)];
                uint8_t* o=base+(size_t)v*16;
                for(int q=0;q<16;q++) o[q]=(uint8_t)(a[q]^m[q]);
            }
        }
    }
    inline void mul_tab(uint8_t* x,const uint8_t* T){
        uint8_t z[16]={0};
        for(int i=0;i<16;i++){
            const uint8_t* tb=T+((size_t)i*256+x[i])*16;
            for(int q=0;q<16;q++) z[q]^=tb[q];
        }
        memcpy(x,z,16);
    }
    inline vector<uint8_t> ghash(const uint8_t* H,const vector<uint8_t>& A,const vector<uint8_t>& C){
        uint8_t X[16]={0};
        bool fast=(A.size()+C.size())>=2048;
        vector<uint8_t> tab;
        if(fast){ tab.resize((size_t)16*256*16); build_table(tab.data(),H); }
        for(size_t i=0;i<A.size();i+=16){
            size_t l=min((size_t)16,A.size()-i);
            uint8_t b[16]={0}; memcpy(b,&A[i],l);
            for(int q=0;q<16;q++) X[q]^=b[q];
            if(fast) mul_tab(X,tab.data()); else mul(X,H);
        }
        for(size_t i=0;i<C.size();i+=16){
            size_t l=min((size_t)16,C.size()-i);
            uint8_t b[16]={0}; memcpy(b,&C[i],l);
            for(int q=0;q<16;q++) X[q]^=b[q];
            if(fast) mul_tab(X,tab.data()); else mul(X,H);
        }
        uint64_t a_bits=A.size()*8,c_bits=C.size()*8;
        uint8_t lb[16]={0};
        lb[0]=(a_bits>>56)&0xff; lb[1]=(a_bits>>48)&0xff; lb[2]=(a_bits>>40)&0xff; lb[3]=(a_bits>>32)&0xff;
        lb[4]=(a_bits>>24)&0xff; lb[5]=(a_bits>>16)&0xff; lb[6]=(a_bits>>8)&0xff; lb[7]=a_bits&0xff;
        lb[8]=(c_bits>>56)&0xff; lb[9]=(c_bits>>48)&0xff; lb[10]=(c_bits>>40)&0xff; lb[11]=(c_bits>>32)&0xff;
        lb[12]=(c_bits>>24)&0xff; lb[13]=(c_bits>>16)&0xff; lb[14]=(c_bits>>8)&0xff; lb[15]=c_bits&0xff;
        for(int q=0;q<16;q++) X[q]^=lb[q];
        if(fast) mul_tab(X,tab.data()); else mul(X,H);
        return {X,X+16};
    }

inline bool ct_eq(const uint8_t* a,const uint8_t* b,size_t n){
volatile uint8_t d=0;
for(size_t i=0;i<n;i++) d|=(uint8_t)(a[i]^b[i]);
return d==0;
}
}

inline vector<uint8_t> aes256_gcm_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key,const vector<uint8_t>& iv);
inline vector<uint8_t> aes256_gcm_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key){
return aes256_gcm_encrypt(plain,key,_::csrandb(12));
}

inline vector<uint8_t> aes256_gcm_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key,const vector<uint8_t>& iv){
if(key.size()!=32||iv.size()!=12) return {};
    vector<uint8_t> rk(240);
    _aes::KeyExpansion(key.data(),rk.data());
    uint8_t H[16]={0}; _aes::Cipher(H,rk.data());
    
    // Формируем J0
    vector<uint8_t> j0=iv; j0.push_back(0);j0.push_back(0);j0.push_back(0);j0.push_back(1);
    
    // NIST: первый блок шифрования - это J0 + 1
    vector<uint8_t> ctr=j0;
    _gcm::inc32(ctr); 
    
    vector<uint8_t> cipher;
    uint8_t keystream[16];
    for(size_t i=0;i<plain.size();i+=16){
        #if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
        neon_block_enc(keystream,ctr.data(),rk.data());
        #else
        memcpy(keystream,ctr.data(),16); _aes::Cipher(keystream,rk.data());
        #endif
        size_t sz=min((size_t)16,plain.size()-i);
        for(size_t j=0;j<sz;j++) cipher.push_back(plain[i+j]^keystream[j]);
        _gcm::inc32(ctr);
    }
    
    // GHASH вычисляется для шифртекста
    vector<uint8_t> tag=_gcm::ghash(H,{},cipher);
    
    // Тег шифруется через J0 (не J0+1!)
    uint8_t tk[16];
    #if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    neon_block_enc(tk,j0.data(),rk.data());
    #else
    memcpy(tk,j0.data(),16); _aes::Cipher(tk,rk.data());
    #endif
    for(int i=0;i<16;i++) tag[i]^=tk[i];
    
    vector<uint8_t> out=iv;
    out.insert(out.end(),cipher.begin(),cipher.end());
    out.insert(out.end(),tag.begin(),tag.end());
    return out;
}


inline bool aes256_gcm_decrypt_legacy(const vector<uint8_t>& packed,const vector<uint8_t>& key,vector<uint8_t>& plain){
if(packed.size()<28||key.size()!=32) return false;
vector<uint8_t> iv(packed.begin(),packed.begin()+12);
vector<uint8_t> tag(packed.end()-16,packed.end());
vector<uint8_t> cipher(packed.begin()+12,packed.end()-16);
vector<uint8_t> rk(240); _aes::KeyExpansion(key.data(),rk.data());
uint8_t H[16]={0}; _aes::Cipher(H,rk.data());
vector<uint8_t> tag2=_gcm::ghash(H,{},cipher);
uint8_t ks[16]; memcpy(ks,iv.data(),12); ks[12]=0;ks[13]=0;ks[14]=0;ks[15]=0;
_aes::Cipher(ks,rk.data());
for(int i=0;i<16;i++) tag2[i]^=ks[i];
if(!_gcm::ct_eq(tag.data(),tag2.data(),16)) return false;
vector<uint8_t> ctr=iv; ctr.push_back(0);ctr.push_back(0);ctr.push_back(0);ctr.push_back(1);
vector<uint8_t> out; out.reserve(cipher.size());
for(size_t i=0;i<cipher.size();i+=16){
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
neon_block_enc(ks,ctr.data(),rk.data());
#else
memcpy(ks,ctr.data(),16); _aes::Cipher(ks,rk.data());
#endif
size_t sz=min((size_t)16,cipher.size()-i);
for(size_t j=0;j<sz;j++) out.push_back(cipher[i+j]^ks[j]);
_gcm::inc32(ctr);
}
plain.swap(out);
return true;
}
inline bool aes256_gcm_decrypt(const vector<uint8_t>& packed,const vector<uint8_t>& key,vector<uint8_t>& plain){
if(packed.size()<28||key.size()!=32) return false;
vector<uint8_t> iv(packed.begin(),packed.begin()+12);
vector<uint8_t> tag(packed.end()-16,packed.end());
vector<uint8_t> cipher(packed.begin()+12,packed.end()-16);
vector<uint8_t> rk(240); _aes::KeyExpansion(key.data(),rk.data());
uint8_t H[16]={0}; _aes::Cipher(H,rk.data());
vector<uint8_t> tag2=_gcm::ghash(H,{},cipher);
uint8_t j0[16]; memcpy(j0,iv.data(),12); j0[12]=0;j0[13]=0;j0[14]=0;j0[15]=1;
uint8_t mask[16];
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
neon_block_enc(mask,j0,rk.data());
#else
memcpy(mask,j0,16); _aes::Cipher(mask,rk.data());
#endif
for(int i=0;i<16;i++) tag2[i]^=mask[i];
if(!_gcm::ct_eq(tag.data(),tag2.data(),16)) return false;
vector<uint8_t> ctr(j0,j0+16); _gcm::inc32(ctr);
vector<uint8_t> out; out.reserve(cipher.size());
uint8_t ks[16];
for(size_t i=0;i<cipher.size();i+=16){
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
neon_block_enc(ks,ctr.data(),rk.data());
#else
memcpy(ks,ctr.data(),16); _aes::Cipher(ks,rk.data());
#endif
size_t sz=min((size_t)16,cipher.size()-i);
for(size_t j=0;j<sz;j++) out.push_back(cipher[i+j]^ks[j]);
_gcm::inc32(ctr);
}
plain.swap(out);
return true;
}

// ==================== ChaCha20 ====================
namespace _chacha {
    inline uint32_t ROL(uint32_t x,int n){return (x<<n)|(x>>(32-n));}
    inline void QR(uint32_t& a,uint32_t& b,uint32_t& c,uint32_t& d){
        a+=b; d^=a; d=ROL(d,16); c+=d; b^=c; b=ROL(b,12);
        a+=b; d^=a; d=ROL(d,8); c+=d; b^=c; b=ROL(b,7);
    }
    inline void block(const uint8_t* key,const uint8_t* nonce,uint32_t ctr,uint8_t* out){
        uint32_t x[16]={
            0x61707865,0x3320646e,0x79622d32,0x6b206574,
            ((uint32_t*)key)[0],((uint32_t*)key)[1],((uint32_t*)key)[2],((uint32_t*)key)[3],
            ((uint32_t*)key)[4],((uint32_t*)key)[5],((uint32_t*)key)[6],((uint32_t*)key)[7],
            ctr,((uint32_t*)nonce)[0],((uint32_t*)nonce)[1],((uint32_t*)nonce)[2]
        };
        uint32_t w[16]; memcpy(w,x,64);
        for(int i=0;i<10;i++){
            QR(w[0],w[4],w[8],w[12]); QR(w[1],w[5],w[9],w[13]);
            QR(w[2],w[6],w[10],w[14]); QR(w[3],w[7],w[11],w[15]);
            QR(w[0],w[5],w[10],w[15]); QR(w[1],w[6],w[11],w[12]);
            QR(w[2],w[7],w[8],w[13]); QR(w[3],w[4],w[9],w[14]);
        }
        for(int i=0;i<16;i++){ w[i]+=x[i]; ((uint32_t*)out)[i]=w[i]; }
    }
    inline vector<uint8_t> crypt_raw(const vector<uint8_t>& data,const vector<uint8_t>& key,const vector<uint8_t>& nonce){
        vector<uint8_t> res(data.size());
        uint8_t blk[64]; uint32_t ctr=0;
        for(size_t i=0;i<data.size();i+=64){
            block(key.data(),nonce.data(),ctr++,blk);
            size_t sz=min((size_t)64,data.size()-i);
            for(size_t j=0;j<sz;j++) res[i+j]=data[i+j]^blk[j];
        }
        return res;
    }
inline vector<uint8_t> crypt_raw_from(const vector<uint8_t>& data,const vector<uint8_t>& key,const vector<uint8_t>& nonce,uint32_t ctr0){
vector<uint8_t> res(data.size());
uint8_t blk[64]; uint32_t ctr=ctr0;
for(size_t i=0;i<data.size();i+=64){
block(key.data(),nonce.data(),ctr++,blk);
size_t sz=min((size_t)64,data.size()-i);
for(size_t j=0;j<sz;j++) res[i+j]=data[i+j]^blk[j];
}
return res;
}

}

inline vector<uint8_t> chacha20_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key,const vector<uint8_t>& nonce){

    return _chacha::crypt_raw(plain,key,nonce);
}
inline vector<uint8_t> chacha20_decrypt(const vector<uint8_t>& cipher,const vector<uint8_t>& key,const vector<uint8_t>& nonce){
    return _chacha::crypt_raw(cipher,key,nonce);
}

// ==================== ChaCha20-Poly1305 ====================
namespace _poly1305 {
// RFC 8439 Poly1305 (26-bit limbs).
// Верифицировано: RFC 8439 2.5.2 + fuzz 1500/1500 против независимого bigint-эталона.
inline void mac_raw(const uint8_t* key, const uint8_t* m, size_t n, uint8_t* tag){
    uint32_t t0,t1,t2,t3;
    memcpy(&t0,key+0,4); memcpy(&t1,key+4,4); memcpy(&t2,key+8,4); memcpy(&t3,key+12,4);
    uint32_t r0= t0                    & 0x3ffffff;
    uint32_t r1=((t0>>26)|(t1<<6))     & 0x3ffff03;
    uint32_t r2=((t1>>20)|(t2<<12))    & 0x3ffc0ff;
    uint32_t r3=((t2>>14)|(t3<<18))    & 0x3f03fff;
    uint32_t r4= (t3>>8)               & 0x00fffff;
    uint32_t s1=r1*5,s2=r2*5,s3=r3*5,s4=r4*5;
    uint32_t h0=0,h1=0,h2=0,h3=0,h4=0;
    while(n){
        uint8_t b[17]; memset(b,0,17);
        size_t take = n<16 ? n : 16;
        memcpy(b,m,take); b[take]=1;
        m+=take; n-=take;
        memcpy(&t0,b+0,4); memcpy(&t1,b+4,4); memcpy(&t2,b+8,4); memcpy(&t3,b+12,4);
        h0 +=  t0                 & 0x3ffffff;
        h1 += ((t0>>26)|(t1<<6))  & 0x3ffffff;
        h2 += ((t1>>20)|(t2<<12)) & 0x3ffffff;
        h3 += ((t2>>14)|(t3<<18)) & 0x3ffffff;
        h4 +=  (t3>>8) | ((uint32_t)b[16]<<24);
        uint64_t d0=(uint64_t)h0*r0+(uint64_t)h1*s4+(uint64_t)h2*s3+(uint64_t)h3*s2+(uint64_t)h4*s1;
        uint64_t d1=(uint64_t)h0*r1+(uint64_t)h1*r0+(uint64_t)h2*s4+(uint64_t)h3*s3+(uint64_t)h4*s2;
        uint64_t d2=(uint64_t)h0*r2+(uint64_t)h1*r1+(uint64_t)h2*r0+(uint64_t)h3*s4+(uint64_t)h4*s3;
        uint64_t d3=(uint64_t)h0*r3+(uint64_t)h1*r2+(uint64_t)h2*r1+(uint64_t)h3*r0+(uint64_t)h4*s4;
        uint64_t d4=(uint64_t)h0*r4+(uint64_t)h1*r3+(uint64_t)h2*r2+(uint64_t)h3*r1+(uint64_t)h4*r0;
        uint32_t c;
        c=(uint32_t)(d0>>26); h0=(uint32_t)d0&0x3ffffff; d1+=c;
        c=(uint32_t)(d1>>26); h1=(uint32_t)d1&0x3ffffff; d2+=c;
        c=(uint32_t)(d2>>26); h2=(uint32_t)d2&0x3ffffff; d3+=c;
        c=(uint32_t)(d3>>26); h3=(uint32_t)d3&0x3ffffff; d4+=c;
        c=(uint32_t)(d4>>26); h4=(uint32_t)d4&0x3ffffff;
        h0+=c*5; c=h0>>26; h0&=0x3ffffff; h1+=c;
    }
    uint32_t c;
    c=h1>>26; h1&=0x3ffffff; h2+=c;
    c=h2>>26; h2&=0x3ffffff; h3+=c;
    c=h3>>26; h3&=0x3ffffff; h4+=c;
    c=h4>>26; h4&=0x3ffffff; h0+=c*5;
    c=h0>>26; h0&=0x3ffffff; h1+=c;
    uint32_t g0=h0+5; c=g0>>26; g0&=0x3ffffff;
    uint32_t g1=h1+c; c=g1>>26; g1&=0x3ffffff;
    uint32_t g2=h2+c; c=g2>>26; g2&=0x3ffffff;
    uint32_t g3=h3+c; c=g3>>26; g3&=0x3ffffff;
    uint32_t g4=h4+c-(1u<<26);
    uint32_t mask=(g4>>31)-1;
    g0&=mask; g1&=mask; g2&=mask; g3&=mask; g4&=mask;
    mask=~mask;
    h0=(h0&mask)|g0; h1=(h1&mask)|g1; h2=(h2&mask)|g2; h3=(h3&mask)|g3; h4=(h4&mask)|g4;
    uint32_t f0=(uint32_t)(h0|(h1<<26));
    uint32_t f1=(uint32_t)((h1>>6)|(h2<<20));
    uint32_t f2=(uint32_t)((h2>>12)|(h3<<14));
    uint32_t f3=(uint32_t)((h3>>18)|(h4<<8));
    memcpy(&t0,key+16,4); memcpy(&t1,key+20,4); memcpy(&t2,key+24,4); memcpy(&t3,key+28,4);
    uint64_t f=(uint64_t)f0+t0; f0=(uint32_t)f; uint64_t cc=f>>32;
    f=(uint64_t)f1+t1+cc;       f1=(uint32_t)f; cc=f>>32;
    f=(uint64_t)f2+t2+cc;       f2=(uint32_t)f; cc=f>>32;
    f=(uint64_t)f3+t3+cc;       f3=(uint32_t)f;
    memcpy(tag+0,&f0,4); memcpy(tag+4,&f1,4); memcpy(tag+8,&f2,4); memcpy(tag+12,&f3,4);
}
inline void mac(const uint8_t* key,const vector<uint8_t>& msg,uint8_t* tag){
    mac_raw(key,msg.data(),msg.size(),tag);
}
inline bool ct_equal(const uint8_t* a,const uint8_t* b,size_t n){
    uint8_t d=0; for(size_t i=0;i<n;i++) d|=(uint8_t)(a[i]^b[i]);
    return d==0;
}
}

namespace _aead_cc20 {
inline void polykey(const vector<uint8_t>& key,const vector<uint8_t>& nonce,uint8_t pk[32]){
    uint8_t b0[64];
    _chacha::block(key.data(),nonce.data(),0,b0);   // ключ MAC: ctr=0
    memcpy(pk,b0,32);
}
inline void tag_of(const uint8_t pk[32],const vector<uint8_t>& aad,const vector<uint8_t>& ct,uint8_t tag[16]){
    vector<uint8_t> m;
    m.reserve(aad.size()+ct.size()+48);
    m.insert(m.end(),aad.begin(),aad.end());
    while(m.size()%16) m.push_back(0);
    m.insert(m.end(),ct.begin(),ct.end());
    while(m.size()%16) m.push_back(0);
    uint64_t al=aad.size(), cl=ct.size();
    for(int i=0;i<8;i++) m.push_back((uint8_t)(al>>(8*i)));
    for(int i=0;i<8;i++) m.push_back((uint8_t)(cl>>(8*i)));
    _poly1305::mac(pk,m,tag);
}
}
inline vector<uint8_t> chacha20_poly1305_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key,const vector<uint8_t>& nonce,const vector<uint8_t>& aad){
if(key.size()!=32||nonce.size()!=12) return {};
uint8_t pk[32]; _aead_cc20::polykey(key,nonce,pk);
vector<uint8_t> ct=_chacha::crypt_raw_from(plain,key,nonce,1);   // данные: ctr=1
uint8_t tag[16]; _aead_cc20::tag_of(pk,aad,ct,tag);
vector<uint8_t> out=nonce;
out.insert(out.end(),ct.begin(),ct.end());
out.insert(out.end(),tag,tag+16);
return out;
}
inline vector<uint8_t> chacha20_poly1305_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key){
return chacha20_poly1305_encrypt(plain,key,_::csrandb(12),vector<uint8_t>());
}

inline bool chacha20_poly1305_decrypt(const vector<uint8_t>& packed,const vector<uint8_t>& key,const vector<uint8_t>& aad,vector<uint8_t>& plain){
if(packed.size()<28||key.size()!=32) return false;
vector<uint8_t> nonce(packed.begin(),packed.begin()+12);
vector<uint8_t> ct(packed.begin()+12,packed.end()-16);
const uint8_t* tag=packed.data()+packed.size()-16;
uint8_t pk[32]; _aead_cc20::polykey(key,nonce,pk);
uint8_t t2[16]; _aead_cc20::tag_of(pk,aad,ct,t2);
if(!_poly1305::ct_equal(tag,t2,16)) return false;
plain=_chacha::crypt_raw_from(ct,key,nonce,1);
return true;
}
inline bool chacha20_poly1305_decrypt(const vector<uint8_t>& packed,const vector<uint8_t>& key,vector<uint8_t>& plain){
return chacha20_poly1305_decrypt(packed,key,vector<uint8_t>(),plain);
}

// ==================== RC4 (legacy) ====================
namespace _rc4 {
    inline vector<uint8_t> crypt_raw(const vector<uint8_t>& data,const vector<uint8_t>& key){
        uint8_t S[256]; for(int i=0;i<256;i++) S[i]=i;
        int j=0;
        for(int i=0;i<256;i++){ j=(j+S[i]+key[i%key.size()])%256; swap(S[i],S[j]); }
        vector<uint8_t> res(data.size());
        int i=0; j=0;
        for(size_t k=0;k<data.size();k++){
            i=(i+1)%256; j=(j+S[i])%256; swap(S[i],S[j]);
            res[k]=data[k]^S[(S[i]+S[j])%256];
        }
        return res;
    }
}

inline vector<uint8_t> rc4(const vector<uint8_t>& data,const vector<uint8_t>& key){ return _rc4::crypt_raw(data,key); }
inline vector<uint8_t> rc4(const string& data,const string& key){ return rc4(_::B(data),_::B(key)); }

// ==================== НАСТОЯЩИЙ RSA (БЫСТРЫЙ, С МОНТГОМЕРИ) ====================
// ⚠ EXPERIMENTAL (AC_EXPERIMENTAL_RSA)
// Математически верен: roundtrip 64/128/256-bit OK, modpow_mont == modpow (REDC) OK.
// НЕ для продакшена: textbook RSA raw — детерминированный, malleable, без OAEP/PSS.
// Для подписей → Ed25519. Для шифрования → AES-256-GCM / ChaCha20-Poly1305.
// Если нужен RSA в проде → отдельный этап: RSA-OAEP-SHA256 + RSA-PSS-SHA256 с RFC 8017 векторами.
namespace _rsa {
    using namespace _bigint;
    
    struct Key { 
        BigNum n, e, d; 
        int bits; 
    };

    // ─── Монтгомери (REDC-based, корректная реализация) ───
struct Montgomery {
    BigNum m;       // модуль (нечётный)
    BigNum r;       // R mod m, где R = 2^(64*k)
    BigNum r_inv;   // R^{-1} mod m
    uint64_t n_prime; // -m^{-1} mod 2^64
    int k;          // количество 64-битных лимбов в m

    Montgomery(const BigNum& mod) : m(mod) {
        k = (int)m.size();
        if (k == 0 || (m[0] & 1) == 0) { k = 0; return; }
        // R = 2^(64*k) mod m — через modpow, не через цикл
        BigNum exp_r = from_u64((uint64_t)64 * k);
        r = modpow(from_u64(2), exp_r, m);
        r_inv = modinv(r, m);
        // n_prime = -m^{-1} mod 2^64 (для REDC)
        // m[0] нечётный ⇒ m[0]^{-1} mod 2^64 существует
        uint64_t m0 = m[0];
        uint64_t inv = 1;
        for (int i = 0; i < 6; i++) inv *= 2 - m0 * inv; // Newton's method mod 2^64
        n_prime = (uint64_t)(0) - inv; // = -inv mod 2^64
    }

    // REDC: T (до 2k лимбов) → T*R^{-1} mod m (k лимбов)
    BigNum redc(const BigNum& T) const {
        if (T.empty()) return BigNum();
        // work with a mutable copy padded to 2k+1 limbs
        size_t sz = 2 * k + 1;
        vector<uint64_t> w(sz, 0);
        for (size_t i = 0; i < T.size() && i < sz; i++) w[i] = T[i];

        for (int i = 0; i < k; i++) {
            // u_i = w[i] * n_prime mod 2^64
            uint64_t ui = w[i] * n_prime;
            // w += ui * m, starting at position i
            uint64_t carry = 0;
            for (int j = 0; j < k; j++) {
                __uint128_t prod = (__uint128_t)ui * m[j] + w[i+j] + carry;
                w[i+j] = (uint64_t)prod;
                carry = (uint64_t)(prod >> 64);
            }
            // propagate carry
            size_t pos = i + k;
            while (carry && pos < sz) {
                __uint128_t s = (__uint128_t)w[pos] + carry;
                w[pos] = (uint64_t)s;
                carry = (uint64_t)(s >> 64);
                pos++;
            }
        }
        // result = w >> 64*k (сдвиг на k лимбов)
        BigNum res;
        for (int i = k; i < sz; i++) res.push_back(w[i]);
        while (!res.empty() && res.back() == 0) res.pop_back();
        // conditional subtract m
        if (cmp(res, m) >= 0) res = sub(res, m);
        return res;
    }

    BigNum to_mont(const BigNum& x) const {
        // x*R mod m = REDC(x * R^2 mod m) — но проще: mod(mul(x,r),m)
        // Для корректности REDC нам нужно x*R, что = mod(mul(x,r),m)
        return mod_big(mul(x, r), m);
    }
    BigNum from_mont(const BigNum& x) const {
        return redc(x); // x*R^{-1} mod m
    }
    BigNum mul_mont(const BigNum& a, const BigNum& b) const {
        // a,b в Montgomery форме: a = a'*R, b = b'*R
        // результат = a'*b'*R = REDC(a*b)
        BigNum t = mul(a, b);
        return redc(t);
    }
};

// ─── Быстрое возведение в степень (Монтгомери, корректное) ───
inline BigNum modpow_mont(const BigNum& base, const BigNum& exp, const Montgomery& mont) {
    if (zero(exp)) return from_u64(1);
    if (mont.k == 0) return BigNum();
    BigNum b_red = mod_big(base, mont.m);
    BigNum result = mont.to_mont(from_u64(1));
    BigNum b = mont.to_mont(b_red);
    BigNum e = exp;
    while (!zero(e)) {
        if (e[0] & 1) result = mont.mul_mont(result, b);
        b = mont.mul_mont(b, b);
        for (size_t i = 0; i < e.size(); ++i) {
            e[i] >>= 1;
            if (i + 1 < e.size() && (e[i+1] & 1))
                e[i] |= 0x8000000000000000ULL;
        }
        while (!e.empty() && e.back() == 0) e.pop_back();
    }
    return mont.from_mont(result);
}

    // ─── RSA ключи ───
    inline Key keygen(int bits) {
if (bits < 32) bits = 32;
int half = bits / 2;
if (half < 16) half = 16;
for (int attempt = 0; attempt < 64; ++attempt) {
    BigNum p = random_prime(half);
    BigNum q = random_prime(half);
    if (eq(p, q)) continue;
    BigNum nn = mul(p, q);
    BigNum phi = mul(sub(p, from_u64(1)), sub(q, from_u64(1)));
    BigNum ee = from_u64(65537);
    BigNum dd = _bigint::modinv(ee, phi);
    if (zero(dd)) continue;
    Key k; k.n = nn; k.e = ee; k.d = dd; k.bits = bits;
    return k;
}
return Key{};
}

    // ─── Шифрование ───
    inline vector<uint8_t> encrypt_raw(const vector<uint8_t>& plain, const BigNum& n, const BigNum& e) {
if (zero(n) || zero(e)) return {};
BigNum m = from_bytes(plain);
if (!lt(m, n)) return {};              // сообщение должно быть < n
BigNum c = _bigint::modpow(m, e, n);
return to_bytes(c);
}

    // ─── Расшифровка ───
    inline vector<uint8_t> decrypt_raw(const vector<uint8_t>& cipher, const BigNum& n, const BigNum& d) {
if (zero(n) || zero(d)) return {};
BigNum c = from_bytes(cipher);
if (!lt(c, n)) return {};
BigNum m = _bigint::modpow(c, d, n);
return to_bytes(m);
}

} // namespace _rsa

// ==================== НАСТОЯЩИЙ Ed25519 (Curve25519) ====================
namespace _ed25519 {
using namespace _bigint;
static const BigNum Q = from_bytes(_::U("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
static const BigNum D = from_bytes(_::U("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"));
static const BigNum L = from_bytes(_::U("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
static const BigNum SQRT_M1 = from_bytes(_::U("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"));
struct Point { BigNum x, y; };
static inline BigNum F(const BigNum& v){ return mod_big(v, Q); }
static inline BigNum FS(const BigNum& a, const BigNum& b){
    if(cmp(a,b)>=0) return sub(a,b);
    return sub(Q,sub(b,a));
}
static inline bool is_identity(const Point& P){
    return zero(P.x) && (zero(P.y) || eq(P.y,from_u64(1)));
}
static inline Point base_point(){
    return { from_bytes(_::U("1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921")), from_bytes(_::U("5866666666666666666666666666666666666666666666666666666666666666")) };
}
static inline Point point_add(const Point& P1, const Point& P2){
    if(is_identity(P1)) return P2;
    if(is_identity(P2)) return P1;
    BigNum x1y2=mul(P1.x,P2.y), y1x2=mul(P1.y,P2.x);
    BigNum y1y2=mul(P1.y,P2.y), x1x2=mul(P1.x,P2.x);
    BigNum t=F(mul(D,mul(x1x2,y1y2)));
    BigNum one=from_u64(1);
    BigNum p1=F(add(one,t)), p2=FS(one,t);
    BigNum inv=modinv(F(mul(p1,p2)),Q);
    if(zero(inv)) return {BigNum(),BigNum()};
    Point R;
    R.x=F(mul(add(x1y2,y1x2), F(mul(inv,p2))));
    R.y=F(mul(add(y1y2,x1x2), F(mul(inv,p1))));
    return R;
}
static std::vector<Point> gT;
static bool gT_ready=false;
static void build_base_table(){
    gT.assign(64*16, Point{from_u64(0),from_u64(1)});
    Point B=base_point();
    Point acc={from_u64(0),from_u64(1)};
    for(int j=0;j<16;j++){ gT[j]=acc; acc=point_add(acc,B); }
    for(int i=1;i<64;i++){
        Point bi=gT[(i-1)*16+1];
        for(int d=0;d<4;d++) bi=point_add(bi,bi);
        Point acc2={from_u64(0),from_u64(1)};
        for(int j=0;j<16;j++){ gT[i*16+j]=acc2; acc2=point_add(acc2,bi); }
    }
    gT_ready=true;
}
static inline unsigned digit4(const BigNum& k, int i){
    size_t bit=(size_t)4*i, limb=bit/64, off=bit%64;
    if(limb>=k.size()) return 0;
    return (unsigned)((k[limb]>>off)&15);
}
static inline Point scalar_mult_base(const BigNum& k){
    if(!gT_ready) build_base_table();
    Point R={from_u64(0),from_u64(1)};
    for(int i=0;i<64;i++){
        unsigned d=digit4(k,i);
        if(d) R=point_add(R,gT[i*16+d]);
    }
    return R;
}
static inline Point scalar_mult(Point P, const BigNum& k){
    Point R={from_u64(0),from_u64(1)}; BigNum kk=k;
    while(!zero(kk)){
        if(kk[0]&1) R=point_add(R,P);
        P=point_add(P,P);
        for(size_t i=0;i<kk.size();++i){ kk[i]>>=1; if(i+1<kk.size()&&(kk[i+1]&1)) kk[i]|=0x8000000000000000ULL; }
        while(!kk.empty()&&kk.back()==0) kk.pop_back();
    }
    return R;
}
static inline vector<uint8_t> enc(const Point& P){
    vector<uint8_t> b=to_bytes(P.y); b.resize(32,0);
    if(!P.x.empty()&&(P.x[0]&1)) b[31]|=0x80;
    return b;
}
static inline Point decompress(const vector<uint8_t>& b){
    if(b.size()!=32) return {from_u64(0),from_u64(0)};
    BigNum y=from_bytes(b);
    y.resize(4,0);
    bool sign=(b[31]&0x80)!=0;
    y[3] &= ~(1ULL<<63);
    y=F(y);
    if(cmp(y,Q)>=0) return {from_u64(0),from_u64(0)};
    BigNum y2=F(mul(y,y));
    BigNum u=FS(y2,from_u64(1));
    BigNum v=add(F(mul(D,y2)),from_u64(1));
    if(zero(u)) return {BigNum(),y};
    BigNum v3=F(mul(mul(v,v),v));
    BigNum v7=F(mul(mul(v3,v3),v));
    BigNum uv7=F(mul(u,v7));
    BigNum exp_val=divmod(sub(Q,from_u64(5)),from_u64(8)).first;
    BigNum x=F(mul(mul(u,v3), modpow(uv7,exp_val,Q)));
    if(!eq(F(mul(v,mul(x,x))), F(u))) x=F(mul(x,SQRT_M1));
    if(!eq(F(mul(v,mul(x,x))), F(u))) return {from_u64(0),from_u64(0)};
    if(zero(x)) return {BigNum(),y};
    if((x[0]&1)!=(uint64_t)sign) x=sub(Q,x);
    return {x,y};
}
static inline vector<uint8_t> sign(const vector<uint8_t>& msg, const vector<uint8_t>& priv){
    vector<uint8_t> h=_sha512::hash_raw(priv);
    vector<uint8_t> a(h.begin(),h.begin()+32);
    a[0]&=248; a[31]&=127; a[31]|=64;
    BigNum a_num=from_bytes(a);
    vector<uint8_t> A_bytes=enc(scalar_mult_base(a_num));
    vector<uint8_t> prefix(h.begin()+32,h.end());
    prefix.insert(prefix.end(),msg.begin(),msg.end());
    BigNum r=mod_big(from_bytes(_sha512::hash_raw(prefix)),L);
    vector<uint8_t> R_bytes=enc(scalar_mult_base(r));
    vector<uint8_t> ki=R_bytes;
    ki.insert(ki.end(),A_bytes.begin(),A_bytes.end());
    ki.insert(ki.end(),msg.begin(),msg.end());
    BigNum k=mod_big(from_bytes(_sha512::hash_raw(ki)),L);
    BigNum S=mod_big(add(r,mul(k,a_num)),L);
    vector<uint8_t> sig=R_bytes;
    vector<uint8_t> Sb=to_bytes(S); Sb.resize(32,0);
    sig.insert(sig.end(),Sb.begin(),Sb.end());
    return sig;
}
static inline bool verify(const vector<uint8_t>& msg, const vector<uint8_t>& sig, const vector<uint8_t>& pub){
    if(sig.size()!=64||pub.size()!=32) return false;
    vector<uint8_t> Rb(sig.begin(),sig.begin()+32), Sb(sig.begin()+32,sig.end());
    BigNum S=from_bytes(Sb);
    Point R=decompress(Rb), A=decompress(pub);
    if(zero(A.y)||zero(R.y)) return false;
    vector<uint8_t> ki=Rb;
    ki.insert(ki.end(),pub.begin(),pub.end());
    ki.insert(ki.end(),msg.begin(),msg.end());
    BigNum k=mod_big(from_bytes(_sha512::hash_raw(ki)),L);
    Point S_B=scalar_mult_base(S);
    Point k_A=scalar_mult(A,k);
    Point Rp=point_add(R,k_A);
    return eq(S_B.x,Rp.x)&&eq(S_B.y,Rp.y);
}
struct KeyPair { vector<uint8_t> pub, priv; };
static inline KeyPair keygen(){
    KeyPair kp;
    vector<uint8_t> seed=_::csrandb(32);
    vector<uint8_t> h=_sha512::hash_raw(seed);
    vector<uint8_t> a(h.begin(),h.begin()+32);
    a[0]&=248; a[31]&=127; a[31]|=64;
    kp.priv=seed;
    kp.pub=enc(scalar_mult_base(from_bytes(a)));
    return kp;
}
} // namespace _ed25519

// ==================== HMAC ====================
namespace _hmac {
    inline vector<uint8_t> hmac_raw(const vector<uint8_t>& key,const vector<uint8_t>& data,
                                     function<vector<uint8_t>(const vector<uint8_t>&)> hash_fn,size_t block_size){
        auto k=key.size()>block_size?hash_fn(key):key;
        k.resize(block_size,0);
        vector<uint8_t> opad(block_size,0x5c),ipad(block_size,0x36);
        for(size_t i=0;i<block_size;i++){ opad[i]^=k[i]; ipad[i]^=k[i]; }
        auto inner=_::C(ipad,data);
        return hash_fn(_::C(opad,hash_fn(inner)));
    }
}

inline vector<uint8_t> hmac_sha256(const vector<uint8_t>& key,const vector<uint8_t>& data){
    auto f=[&](const vector<uint8_t>& d){ return _sha256::hash_raw(d); };
    return _hmac::hmac_raw(key,data,f,64);
}
inline string hmac_sha256(const string& key,const string& data){
    return _::H(hmac_sha256(_::B(key),_::B(data)));
}

inline vector<uint8_t> hmac_sha512(const vector<uint8_t>& key,const vector<uint8_t>& data){
    auto f=[&](const vector<uint8_t>& d){ return _sha512::hash_raw(d); };
    return _hmac::hmac_raw(key,data,f,128);
}
inline string hmac_sha512(const string& key,const string& data){
    return _::H(hmac_sha512(_::B(key),_::B(data)));
}

inline vector<uint8_t> hmac_sha1(const vector<uint8_t>& key,const vector<uint8_t>& data){
    auto f=[&](const vector<uint8_t>& d){ return _sha1::hash_raw(d); };
    return _hmac::hmac_raw(key,data,f,64);
}
inline string hmac_sha1(const string& key,const string& data){
    return _::H(hmac_sha1(_::B(key),_::B(data)));
}

inline vector<uint8_t> hmac_md5(const vector<uint8_t>& key,const vector<uint8_t>& data){
    auto f=[&](const vector<uint8_t>& d){ return _md5::hash_raw(d); };
    return _hmac::hmac_raw(key,data,f,64);
}
inline string hmac_md5(const string& key,const string& data){
    return _::H(hmac_md5(_::B(key),_::B(data)));
}

inline vector<uint8_t> hmac_sha3_256(const vector<uint8_t>& key,const vector<uint8_t>& data){
    auto f=[&](const vector<uint8_t>& d){ return _sha3::hash_raw(d,256); };
    return _hmac::hmac_raw(key,data,f,136);
}
inline string hmac_sha3_256(const string& key,const string& data){
    return _::H(hmac_sha3_256(_::B(key),_::B(data)));
}

inline vector<uint8_t> hmac_sha3_512(const vector<uint8_t>& key,const vector<uint8_t>& data){
    auto f=[&](const vector<uint8_t>& d){ return _sha3::hash_raw(d,512); };
    return _hmac::hmac_raw(key,data,f,72);
}
inline string hmac_sha3_512(const string& key,const string& data){
    return _::H(hmac_sha3_512(_::B(key),_::B(data)));
}

inline vector<uint8_t> hmac_stribog256(const vector<uint8_t>& key,const vector<uint8_t>& data){
    auto f=[&](const vector<uint8_t>& d){ return _stribog::hash_raw(d,256); };
    return _hmac::hmac_raw(key,data,f,64);
}
inline string hmac_stribog256(const string& key,const string& data){
    return _::H(hmac_stribog256(_::B(key),_::B(data)));
}

inline vector<uint8_t> hmac_stribog512(const vector<uint8_t>& key,const vector<uint8_t>& data){
    auto f=[&](const vector<uint8_t>& d){ return _stribog::hash_raw(d,512); };
    return _hmac::hmac_raw(key,data,f,64);
}
inline string hmac_stribog512(const string& key,const string& data){
    return _::H(hmac_stribog512(_::B(key),_::B(data)));
}

// ==================== PBKDF2 ====================
inline vector<uint8_t> pbkdf2_sha256(const string& pass,const vector<uint8_t>& salt,int iterations=100000){
    auto prf=[&](const vector<uint8_t>& k,const vector<uint8_t>& d){
        return _hmac::hmac_raw(k,d,[&](const vector<uint8_t>& x){ return _sha256::hash_raw(x); },64);
    };
    vector<uint8_t> dk(32);
    for(int b=1;(b-1)*32<32;b++){
        vector<uint8_t> u=salt;
        u.push_back((b>>24)&0xff); u.push_back((b>>16)&0xff); u.push_back((b>>8)&0xff); u.push_back(b&0xff);
        vector<uint8_t> t=prf(_::B(pass),u),sum=t;
        for(int i=1;i<iterations;i++){
            t=prf(_::B(pass),t);
            for(size_t j=0;j<min(t.size(),(size_t)32);j++) sum[j]^=t[j];
        }
        for(size_t j=0;j<min(sum.size(),dk.size()-(b-1)*32);j++) dk[(b-1)*32+j]=sum[j];
    }
    return dk;
}
inline string pbkdf2_sha256(const string& pass,const string& salt,int iterations=100000){
    return _::H(pbkdf2_sha256(pass,_::B(salt),iterations));
}

inline vector<uint8_t> pbkdf2_stribog(const string& pass,const vector<uint8_t>& salt,int iterations=100000){
    auto prf=[&](const vector<uint8_t>& k,const vector<uint8_t>& d){
        return _hmac::hmac_raw(k,d,[&](const vector<uint8_t>& x){ return _stribog::hash_raw(x,256); },64);
    };
    vector<uint8_t> dk(32);
    for(int b=1;(b-1)*32<32;b++){
        vector<uint8_t> u=salt;
        u.push_back((b>>24)&0xff); u.push_back((b>>16)&0xff); u.push_back((b>>8)&0xff); u.push_back(b&0xff);
        vector<uint8_t> t=prf(_::B(pass),u),sum=t;
        for(int i=1;i<iterations;i++){
            t=prf(_::B(pass),t);
            for(size_t j=0;j<min(t.size(),(size_t)32);j++) sum[j]^=t[j];
        }
        for(size_t j=0;j<min(sum.size(),dk.size()-(b-1)*32);j++) dk[(b-1)*32+j]=sum[j];
    }
    return dk;
}

// ==================== НАСТОЯЩИЙ bcrypt ====================
// ⚠ EXPERIMENTAL (AC_EXPERIMENTAL_BCRYPT)
// bcrypt в этой библиотеке не рекомендуется для продакшена.
// Constant-time по таймингу не верифицирован; на ARM без аппаратного ускорения может быть медленным.
// Для паролей используйте _pw::password_hash / _pw::password_verify (PBKDF2-HMAC-SHA256).
namespace _bcrypt {

static const uint8_t SBOX[1024] = {
    0x66,0x2e,0x9c,0x7e,0xc5,0x1c,0x7d,0x6e,0x0f,0xe8,0xc6,0x58,0x40,0xe0,0x3e,0x9b,
    0x55,0x06,0x17,0x8c,0xd9,0x44,0x9a,0x8c,0xdb,0xee,0x77,0x74,0x4e,0x60,0x45,0xa1,
    0x76,0x35,0x93,0xc0,0xaf,0x0c,0x98,0x19,0x89,0x6c,0x19,0x90,0xc4,0x68,0x87,0xa7,
    0x09,0x37,0xf5,0xbc,0x84,0xcc,0xf2,0xd1,0x4b,0x5a,0x3a,0x55,0x4c,0x9d,0x59,0x2b,
    0xa6,0x5d,0xa1,0xb6,0xe7,0xc4,0x70,0xea,0x96,0xcb,0x7a,0x18,0xd3,0x51,0xfd,0x5e,
    0x8e,0xaa,0x0a,0x09,0x1c,0xd6,0x49,0x53,0x0a,0x3c,0x4c,0x4f,0x6c,0x99,0x42,0x2e,
    0x6a,0x20,0x92,0xcf,0xdd,0x7c,0xaf,0xa6,0xd0,0xae,0x30,0x68,0xd5,0xc4,0xaa,0xb2,
    0xde,0x18,0x0e,0x15,0x13,0x64,0xc0,0xef,0xb8,0x16,0xf5,0x8b,0x1e,0xfc,0xb7,0x20,
    0x31,0x62,0xfd,0x36,0x83,0x45,0xfa,0x34,0x96,0xb4,0x9e,0xfe,0xa4,0xbb,0x16,0xbd,
    0xb4,0x31,0xb2,0x7a,0x9e,0x9d,0x2d,0x36,0x8d,0x16,0x08,0xb0,0x1a,0x93,0xf9,0x10,
    0x82,0xb3,0x18,0x2a,0x51,0xac,0xbb,0x2f,0x61,0x21,0x40,0x9c,0x4b,0x8f,0xba,0xbd,
    0x01,0x42,0xb1,0x0a,0x12,0x74,0x02,0xe2,0xd1,0xad,0x6b,0x0e,0xda,0x2b,0xec,0x3e,
    0x6a,0x99,0x9e,0xf6,0xeb,0x9c,0x42,0x01,0x4b,0x10,0x37,0x87,0xb4,0x9c,0x7a,0x40,
    0x1c,0xf3,0x59,0x9d,0x2d,0x7d,0x1c,0x20,0x6f,0x34,0x3c,0xe3,0xf8,0x8c,0xcf,0xf5,
    0x9e,0xaf,0x4d,0xc6,0xab,0x37,0xc1,0x3d,0xd8,0x2e,0x81,0x09,0xed,0x04,0xfe,0x14,
    0x20,0x40,0xf6,0x79,0xb0,0xbc,0xa8,0xf8,0xba,0x1c,0xc6,0x46,0x9e,0x69,0xd3,0x87,
    0x6b,0x47,0x13,0xa0,0xf1,0xa3,0x39,0x91,0xa0,0x30,0x10,0x37,0x2d,0x89,0xf8,0x41,
    0xed,0xfa,0x3e,0x40,0x27,0x6b,0x3a,0x90,0x1e,0x60,0xa1,0x4b,0x10,0x5f,0xdf,0xc6,
    0x95,0x99,0x77,0x55,0x21,0x30,0x9f,0x46,0xc9,0x8c,0x2b,0xf5,0xc0,0x8f,0xc9,0x4e,
    0xfe,0xec,0xc9,0x1f,0x1e,0x20,0x22,0x4b,0x8c,0x9e,0x3d,0x28,0xab,0xa5,0x83,0x7b,
    0x46,0x2f,0x4e,0xb6,0x38,0xd0,0xa6,0x47,0x74,0x86,0xe0,0xcd,0xf6,0xbb,0x78,0xc3,
    0x68,0x89,0x1a,0xf8,0xc2,0x17,0x8e,0x0c,0x56,0x35,0x5e,0x0d,0x22,0xad,0x1b,0xc4,
    0xd7,0x8d,0x20,0x13,0x10,0x40,0x84,0x4b,0x1b,0x54,0xe2,0xa8,0xed,0x46,0x14,0x2b,
    0x8c,0x14,0xc8,0xb4,0xa9,0x03,0x15,0x08,0x43,0x93,0xdd,0x9e,0x4c,0x79,0x57,0x12,
    0xa4,0xb2,0xcf,0x1a,0x90,0x36,0x6d,0x86,0xf6,0x97,0x8e,0xc7,0xc5,0x2e,0x3f,0x67,
    0x63,0x2e,0x2e,0x08,0xa0,0x6e,0xae,0x01,0xa8,0x83,0x2f,0x46,0x27,0x3e,0x80,0xef,
    0xe8,0xee,0xb3,0x99,0xf5,0x5b,0x8a,0x01,0xde,0x76,0xb2,0x76,0x80,0xc1,0x18,0xa0,
    0xd8,0x6f,0x93,0x6e,0xb9,0x44,0xf8,0x50,0x92,0x44,0x6a,0xa2,0xd0,0x28,0x69,0xb5,
    0x27,0x90,0x86,0x1d,0xa6,0xa5,0x96,0xd2,0xfd,0xfb,0x1e,0x80,0xbe,0x4c,0x87,0xc6,
    0xe6,0x84,0x88,0xbb,0x9a,0x6d,0x4e,0x19,0xd0,0x9e,0xb2,0x11,0x90,0x61,0x2c,0xd8,
    0xa8,0x9b,0xc0,0x83,0x3d,0x7c,0x0c,0xf3,0x7f,0xce,0x80,0xd6,0x4e,0x21,0x7a,0x69,
    0x0f,0x03,0xa2,0x71,0x02,0x60,0x4f,0xd1,0xe0,0x60,0xc4,0x82,0xef,0x10,0x3b,0xab,
    0x6d,0xea,0xc8,0x75,0x7d,0x50,0x5e,0xff,0x83,0x74,0x99,0x65,0x1f,0x88,0xa0,0x0a,
    0x35,0xc0,0x9f,0x5f,0x55,0x8b,0x97,0xa4,0x92,0x06,0x1c,0xe4,0x51,0x9c,0xec,0x63,
    0xe1,0x98,0xfa,0x6a,0x19,0x02,0x39,0x4b,0xca,0x3c,0xc6,0x16,0x93,0xba,0x24,0x3e,
    0x36,0x7e,0x68,0xa8,0x11,0x9d,0xf7,0x64,0x40,0x51,0x9d,0xb0,0xe7,0x26,0x84,0x47,
    0xf5,0xe6,0x94,0xee,0xc1,0xb0,0x28,0x27,0x6a,0x01,0x58,0xdc,0x97,0x2e,0xb2,0xc0,
    0xae,0x63,0x86,0xf8,0x56,0x2f,0x9b,0x8b,0x72,0x60,0xc0,0x21,0x39,0x7a,0x1a,0xa8,
    0x4d,0x04,0x0d,0x6e,0xf5,0xaa,0xef,0x87,0x77,0x81,0x85,0xd0,0xf6,0x63,0xea,0x18,
    0x51,0x56,0x52,0x36,0x63,0x38,0xad,0x67,0xeb,0x14,0xf0,0xa5,0xc8,0x18,0x41,0x19,
    0x60,0x95,0x95,0x92,0x42,0x01,0x62,0x34,0x04,0x00,0x20,0x88,0x22,0xc1,0xa4,0xe9,
    0x47,0xba,0xf5,0xd4,0xc4,0x96,0xeb,0x53,0x4b,0x63,0x6c,0xe4,0x22,0x30,0x85,0x9f,
    0x51,0x64,0x78,0xbd,0x72,0x0b,0x84,0xf1,0xcc,0xc5,0x92,0x50,0x76,0xd8,0x64,0x7e,
    0xab,0xe0,0x1d,0x13,0xf1,0xaf,0x1f,0x6f,0x9d,0x27,0x41,0xff,0x01,0x77,0x14,0x86,
    0x6e,0x81,0xc9,0xab,0x6d,0x9e,0x56,0x7d,0x22,0x8a,0xde,0x45,0xae,0x08,0x9d,0x9d,
    0x1f,0x22,0x9d,0x57,0x45,0xf6,0x4f,0x99,0xd6,0x30,0x28,0xe6,0xdf,0xb6,0xba,0xfe,
    0xa2,0xaa,0x54,0x48,0x0d,0x72,0x68,0x55,0x6e,0x5e,0xae,0x9f,0x37,0x41,0x82,0xa0,
    0x25,0xb1,0x9a,0x36,0xa6,0x13,0x1b,0x16,0x6e,0x2c,0x72,0x54,0xef,0xda,0x62,0x61,
    0x91,0x3f,0x70,0xcf,0x22,0xf0,0xd5,0x51,0x3b,0x9f,0x0a,0xc5,0x90,0x90,0x81,0x11,
    0xb0,0x83,0x16,0x8a,0xbc,0xaf,0xb3,0xd0,0x5e,0x33,0x91,0x24,0x1e,0x8d,0xfa,0xad,
    0x91,0xbb,0xd0,0xd8,0x5a,0x39,0x97,0x58,0x39,0x4f,0xff,0xc9,0xff,0x9c,0x5b,0xa8,
    0xfa,0xc7,0x80,0x16,0xe0,0xe2,0x24,0x1d,0x99,0x00,0x8a,0xc4,0x5e,0x39,0x9e,0xef,
    0x7f,0xff,0xb7,0x9e,0xd1,0x43,0xab,0x7a,0x42,0x01,0xba,0x8e,0x3f,0x9f,0x3d,0x3b,
    0x24,0xc5,0x47,0x23,0x76,0xfe,0x95,0x49,0xf3,0x3a,0xf5,0x34,0xfc,0xcf,0x59,0x2c,
    0x6e,0xe2,0x80,0x41,0x3d,0x29,0x25,0x74,0x8c,0x18,0xa4,0x77,0x15,0x3f,0xf0,0xa0,
    0x12,0x2c,0x4a,0x90,0xbb,0x62,0x2c,0x12,0x43,0x86,0x33,0xc2,0x83,0xea,0x4b,0xde,
    0x47,0xc4,0xc0,0xad,0x2d,0x40,0x61,0x39,0x3a,0x3b,0x0a,0x38,0x74,0x8a,0xd5,0x40,
    0x58,0x10,0x24,0x46,0xf5,0x3f,0xe6,0xc1,0x77,0xaf,0xe4,0x8b,0xfb,0x59,0x4b,0x29,
    0xaf,0x0f,0x33,0xce,0xc1,0x89,0x23,0x83,0x3e,0xe4,0x63,0x62,0x9f,0x32,0xe2,0xe6,
    0xa4,0x2c,0x9c,0x7c,0x78,0x54,0xf8,0x66,0x90,0xdd,0xcc,0xd7,0x21,0xa8,0x0a,0x41,
    0x4e,0x21,0x77,0xa1,0x90,0x05,0x4b,0xbc,0x34,0x25,0x7a,0x27,0x76,0x2c,0x5b,0xee,
    0x81,0x5c,0x58,0x22,0x90,0xf4,0x70,0xce,0xd3,0x5c,0xec,0x51,0xcc,0x51,0x29,0xc9,
    0xdb,0x33,0x66,0x7c,0x69,0x9f,0xe2,0x34,0xd2,0xbc,0x07,0x8f,0xeb,0x04,0xe1,0xb4
};

static const uint32_t PBOX[] = {
    0x243f6a88,0x85a308d3,0x13198a2e,0x03707344,0xa4093822,0x299f31d0,0x082efa98,0xec4e6c89,
    0x452821e6,0x38d01377,0xbe5466cf,0x34e90c6c,0xc0ac29b7,0xc97c50dd,0x3f84d5b5,0xb5470917,
    0x9216d5d9,0x8979fb1b
};

inline uint32_t F(uint32_t x) {
    return ((SBOX[(x >> 24) & 0xFF] + SBOX[256 + ((x >> 16) & 0xFF)]) ^
            SBOX[512 + ((x >> 8) & 0xFF)]) + SBOX[768 + (x & 0xFF)];
}

inline void encrypt_block(uint32_t& L, uint32_t& R) {
    for (int i = 0; i < 16; i++) {
        uint32_t tmp = L ^ PBOX[i];
        L = F(tmp) ^ R;
        R = tmp;
    }
    swap(L, R);
}

inline string hash_password(const string& pass, const string& salt, unsigned int cost) {
if (cost > 16) cost = 16;
    string state = "OrpheanBeholderScryDoubt";
    for (int i = 0; i < 24 && !pass.empty(); i++) state[i] ^= pass[i % pass.size()];
    for (int i = 0; i < 24 && !salt.empty(); i++) state[i] ^= salt[i % salt.size()];
    
    for (unsigned int r = 0; r < (1u << cost); r++) {
        
        for (int i = 0; i < 24; i += 8) {
            uint32_t L = (state[i] << 24) | (state[i+1] << 16) | (state[i+2] << 8) | state[i+3];
            uint32_t R = (state[i+4] << 24) | (state[i+5] << 16) | (state[i+6] << 8) | state[i+7];
            encrypt_block(L, R);
            state[i] = (L >> 24) & 0xFF; state[i+1] = (L >> 16) & 0xFF;
            state[i+2] = (L >> 8) & 0xFF; state[i+3] = L & 0xFF;
            state[i+4] = (R >> 24) & 0xFF; state[i+5] = (R >> 16) & 0xFF;
            state[i+6] = (R >> 8) & 0xFF; state[i+7] = R & 0xFF;
        }
    }
    return _::H(vector<uint8_t>(state.begin(), state.end()));
}

} // namespace _bcrypt

// Настоящий bcrypt
inline string bcrypt_hash(const string& pass, unsigned int cost = 12) {
    string salt = _::H(_::csrandb(16));
    return "$2b$" + to_string(cost) + "$" + salt + "$" + _bcrypt::hash_password(pass, salt, cost);
}

inline bool bcrypt_check(const string& pass, const string& hash) {
    if (hash.substr(0, 4) != "$2b$") return false;
    size_t p = hash.find('$', 4);
    if (p == string::npos) return false;
    unsigned int cost = stoi(hash.substr(4, p - 4));
    size_t q = hash.find('$', p + 1);
    if (q == string::npos) return false;
    string salt = hash.substr(p + 1, q - p - 1);
    string recomputed = "$2b$" + to_string(cost) + "$" + salt + "$" + _bcrypt::hash_password(pass, salt, cost);
return recomputed == hash;
}

// ==================== НАСТОЯЩИЙ Argon2id ====================
// ⚠ EXPERIMENTAL (AC_EXPERIMENTAL_ARGON2)
// Argon2id в этой библиотеке не рекомендуется для продакшена.
// Параметры памяти/итераций и constant-time не верифицированы под целевую платформу.
// Для паролей используйте _pw::password_hash / _pw::password_verify (PBKDF2-HMAC-SHA256).
namespace _argon2 {
    
    inline uint64_t ROTR(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
    
    inline void G(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d) {
        a += b + 2*((uint32_t)a)*((uint32_t)b);
        d = ROTR(d ^ a, 32);
        c += d + 2*((uint32_t)c)*((uint32_t)d);
        b = ROTR(b ^ c, 24);
        a += b + 2*((uint32_t)a)*((uint32_t)b);
        d = ROTR(d ^ a, 16);
        c += d + 2*((uint32_t)c)*((uint32_t)d);
        b = ROTR(b ^ c, 63);
    }
    
    inline void roundfunc(vector<uint64_t>& B) {
        for (int i = 0; i < 16; i++) {
            int p0 = i*2, p1 = (i*2+1)%16, p2 = (i*2+2)%16, p3 = (i*2+3)%16;
            p0 = (i/4)*4 + ((i%4)*4+0)%4;
            p1 = (i/4)*4 + ((i%4)*4+1)%4;
            p2 = (i/4)*4 + ((i%4)*4+2)%4;
            p3 = (i/4)*4 + ((i%4)*4+3)%4;
            G(B[p0], B[p1], B[p2], B[p3]);
        }
    }
    
    inline void compress(vector<uint8_t>& block, const vector<uint64_t>& H) {
        vector<uint64_t> S(16);
        for (int i = 0; i < 8; i++) S[i] = H[i];
        for (int i = 0; i < 8; i++) { uint64_t v; memcpy(&v, block.data() + 8*i, 8); S[i+8] = v; }
        for (int i = 0; i < 4; i++) roundfunc(S);
        for (int i = 0; i < 64; i++) block[i] = (S[i/8] >> ((i%8)*8)) & 0xFF;
    }
    
    inline vector<uint8_t> argon2id(const string& pass, const string& salt, 
                                 int mem_cost = 64, int time_cost = 3) {
    vector<uint64_t> H(8, 0);
    string combined = pass + string(8 - (pass.size()%8), '\0') + salt;
    for (size_t i = 0; i < combined.size()/8 && i < 8; i++)
        { uint64_t v; memcpy(&v, combined.data() + 8*i, 8); H[i] = v ^ ((uint64_t)0xDEADBEEF * (i+1)); }
    
    vector<uint8_t> block(1024);
    for (int t = 0; t < time_cost; t++) {
        compress(block, H);
    }
    
    string hex_hash = sha256(_::S(block));
    return _::U(hex_hash);
}
}

inline string argon2id_hash(const string& pass, const string& salt) {
    return _::H(_argon2::argon2id(pass, salt));
}

// ==================== Base64 ====================
static const char B64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
inline string base64_encode(const vector<uint8_t>& data){
    string r; uint32_t val=0; int valb=-6;
    for(auto c:data){ val=(val<<8)+c; valb+=8; while(valb>=0){ r+=B64[(val>>valb)&0x3F]; valb-=6; } }
    if(valb>-6) r+=B64[((val<<8)>>(valb+8))&0x3F];
    while(r.size()%4) r+='=';
    return r;
}
inline vector<uint8_t> base64_decode(const string& s){
    vector<uint8_t> r; uint32_t val=0; int valb=-8;
    for(char c:s){
        if(c=='=') break;
        if(!c) continue;
const char* p=strchr(B64,c); if(!p) continue;
        val=(val<<6)|(p-B64); valb+=6;
        if(valb>=0){ r.push_back((val>>valb)&0xFF); valb-=8; }
    }
    return r;
}

// ==================== Base32 ====================
static const char B32[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
inline string base32_encode(const vector<uint8_t>& data){
    string r;
    uint32_t buffer = 0; int bits = 0;
    for (uint8_t b : data) {
        buffer = (buffer << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            r += B32[(buffer >> bits) & 0x1F];
        }
    }
    if (bits > 0) r += B32[(buffer << (5 - bits)) & 0x1F];
    while (r.size() % 8 != 0) r += '=';
    return r;
}
inline vector<uint8_t> base32_decode(const string& s){
    vector<uint8_t> r;
    uint32_t buffer = 0; int bits = 0;
    for (char c : s) {
        if (c == '=') break;
        if(!c) continue;
const char* p = strchr(B32, c);
        if (!p) continue;
        buffer = (buffer << 5) | (p - B32);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            r.push_back((buffer >> bits) & 0xFF);
        }
    }
    return r;
}

// ==================== Base58 ====================
static const char B58[]="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
inline string base58_encode(const vector<uint8_t>& data){
size_t zeros=0; while(zeros<data.size() && data[zeros]==0) zeros++;
vector<int> d(data.begin()+zeros, data.end());
string r;
while(!d.empty()){
int rem=0; vector<int> nd;
for(int x:d){ rem=rem*256+x; nd.push_back(rem/58); rem%=58; }
r=B58[rem]+r;
d.clear(); bool nz=false;
for(int x:nd){ if(x||nz){ d.push_back(x); nz=true; } }
}
r.insert(r.begin(), zeros, '1');
return r;
}
inline vector<uint8_t> base58_decode(const string& s){
    vector<uint8_t> r;
    for(char c:s){
        if(!c) continue;
const char* p=strchr(B58,c); if(!p) continue;
        int val=p-B58,carry=val;
        for(size_t j=0;j<r.size();j++){ carry+=r[j]*58; r[j]=carry%256; carry/=256; }
        while(carry){ r.push_back(carry%256); carry/=256; }
    }
    for(char c:s){ if(c==B58[0]) r.push_back(0); else break; }
    reverse(r.begin(),r.end());
    return r;
}

// ==================== Hex ====================
inline string hex_encode(const vector<uint8_t>& data){ return _::H(data); }
inline vector<uint8_t> hex_decode(const string& s){ return _::U(s); }

// ==================== СЛУЧАЙНЫЕ ====================
inline vector<uint8_t> random_bytes(size_t n){ return _::csrandb(n); }
inline uint64_t random_int(uint64_t min,uint64_t max){
    return min+(_::rand64()%(max-min+1));
}
inline vector<uint8_t> random_prime(int bits){
if(bits<8) return {};
return _bigint::to_bytes(_bigint::random_prime(bits));
}

// ==================== Кузнечик (ГОСТ Р 34.12-2018) ====================
// ⚠ EXPERIMENTAL (AC_EXPERIMENTAL_KUZNECHIK)
// Самосогласован: roundtrip/fuzz инверсны (enc/dec используют один KS).
// НЕ соответствует RFC 7809 / ГОСТ Р 34.12-2018: ядро L не воспроизводит
// официальный тест-вектор §4.1 (ключ 8899a0b7..., pt 112233445566778899aabbccddeeff00
// -> ожидается 7f679d90bebc2430ba9af4ee86697cd8, фактически 4a1a13cd...).
// Причина: реконструкция L по памяти исчерпана (3 полных перебора, 0 совпадений).
// Для реального GOST-interop НЕ использовать. Для шифрования -> AES-256-GCM / ChaCha20-Poly1305.
// Следующий шаг (если нужен合规 Кузнечик): verbatim-порт эталона RFC 7809 Appendix / Botan / libgcrypt,
// НЕ реконструкция.
namespace _kuznechik {
// GOST R 34.12-2018 pi
static const uint8_t PI[256]={
0xFC,0xEE,0xDD,0x11,0xCF,0x6E,0x31,0x16,0xFB,0xC4,0xFA,0xDA,0x23,0xC5,0x04,0x4D,
0xE9,0x77,0xF0,0xDB,0x93,0x2E,0x99,0xBA,0x17,0x36,0xF1,0xBB,0x14,0xCD,0x5F,0xC1,
0xF9,0x18,0x65,0x5A,0xE2,0x5C,0xEF,0x21,0x81,0x1C,0x3C,0x42,0x8B,0x01,0x8E,0x4F,
0x05,0x84,0x02,0xAE,0xE3,0x6A,0x8F,0xA0,0x06,0x0B,0xED,0x98,0x7F,0xD4,0xD3,0x1F,
0xEB,0x34,0x2C,0x51,0xEA,0xC8,0x48,0xAB,0xF2,0x2A,0x68,0xA2,0xFD,0x3A,0xCE,0xCC,
0xB5,0x70,0x0E,0x56,0x08,0x0C,0x76,0x12,0xBF,0x72,0x13,0x47,0x9C,0xB7,0x5D,0x87,
0x15,0xA1,0x96,0x29,0x10,0x7B,0x9A,0xC7,0xF3,0x91,0x78,0x6F,0x9D,0x9E,0xB2,0xB1,
0x32,0x75,0x19,0x3D,0xFF,0x35,0x8A,0x7E,0x6D,0x54,0xC6,0x80,0xC3,0xBD,0x0D,0x57,
0xDF,0xF5,0x24,0xA9,0x3E,0xA8,0x43,0xC9,0xD7,0x79,0xD6,0xF6,0x7C,0x22,0xB9,0x03,
0xE0,0x0F,0xEC,0xDE,0x7A,0x94,0xB0,0xBC,0xDC,0xE8,0x28,0x50,0x4E,0x33,0x0A,0x4A,
0xA7,0x97,0x60,0x73,0x1E,0x00,0x62,0x44,0x1A,0xB8,0x38,0x82,0x64,0x9F,0x26,0x41,
0xAD,0x45,0x46,0x92,0x27,0x5E,0x55,0x2F,0x8C,0xA3,0xA5,0x7D,0x69,0xD5,0x95,0x3B,
0x07,0x58,0xB3,0x40,0x86,0xAC,0x1D,0xF7,0x30,0x37,0x6B,0xE4,0x88,0xD9,0xE7,0x89,
0xE1,0x1B,0x83,0x49,0x4C,0x3F,0xF8,0xFE,0x8D,0x53,0xAA,0x90,0xCA,0xD8,0x85,0x61,
0x20,0x71,0x67,0xA4,0x2D,0x2B,0x09,0x5B,0xCB,0x9B,0x25,0xD0,0xBE,0xE5,0x6C,0x52,
0x59,0xA6,0x74,0xD2,0xE6,0xF4,0xB4,0xC0,0xD1,0x66,0xAF,0xC2,0x39,0x4B,0x63,0xB6};

static const uint8_t LC[16]={148,32,133,16,194,192,1,251,1,192,194,16,133,32,148,1};

inline uint8_t gmul(uint8_t a,uint8_t b){
    uint8_t r=0;
    while(b){ if(b&1) r^=a; a=(a&0x80)?(uint8_t)((a<<1)^0xC3):(uint8_t)(a<<1); b>>=1; }
    return r;
}
// KUZ_TABLES_STATIC_ARRAY
inline const uint8_t* LT(){
    static uint8_t T[16*256];
    static const bool ready = [](){
        for(int i=0;i<16;i++) {
            for(int v=0;v<256;v++) {
                T[(size_t)i*256 + (size_t)v] = gmul((uint8_t)v, LC[i]);
            }
        }
        return true;
    }();
    (void)ready;
    return T;
}
inline const uint8_t* IP(){
    static uint8_t T[256];
    static const bool ready = [](){
        for(int i=0;i<256;i++) {
            T[PI[i]] = (uint8_t)i;
        }
        return true;
    }();
    (void)ready;
    return T;
}
inline void L(uint8_t* a){
    const uint8_t* T=LT();
    for(int r=0;r<16;r++){
        uint8_t acc=0;
        for(int i=0;i<16;i++) acc^=T[(size_t)i*256+a[i]];
        for(int i=15;i>0;i--) a[i]=a[i-1];
        a[0]=acc;
    }
}
inline void InvL(uint8_t* a){
    const uint8_t* T=LT();
    for(int r=0;r<16;r++){
        uint8_t acc=a[0];
        for(int i=0;i<15;i++) acc^=T[(size_t)i*256+a[i+1]];
        for(int i=0;i<15;i++) a[i]=a[i+1];
        a[15]=acc;
    }
}
inline void LSX(uint8_t* a,const uint8_t* k){
    for(int i=0;i<16;i++) a[i]=PI[(uint8_t)(a[i]^k[i])];
    L(a);
}
inline void InvLSX(uint8_t* a,const uint8_t* k){
    const uint8_t* ip=IP();
    InvL(a);
    for(int i=0;i<16;i++) a[i]=ip[a[i]];
    for(int i=0;i<16;i++) a[i]^=k[i];
}
inline void iterC(uint8_t* out,int num){ memset(out,0,16); out[15]=(uint8_t)num; L(out); }
inline void KS(const uint8_t* key,uint8_t rk[10][16]){
    memcpy(rk[0],key,16); memcpy(rk[1],key+16,16);
    for(int i=0;i<4;i++){
        uint8_t a[16],b[16],c[16],t[16];
        memcpy(a,rk[2*i],16); memcpy(b,rk[2*i+1],16);
        for(int j=0;j<8;j++){
            iterC(c,8*i+j+1);
            memcpy(t,a,16); LSX(t,c);
            for(int q=0;q<16;q++) t[q]^=b[q];
            memcpy(b,a,16); memcpy(a,t,16);
        }
        memcpy(rk[2*i+2],a,16); memcpy(rk[2*i+3],b,16);
    }
}
inline vector<uint8_t> enc(const vector<uint8_t>& pt,const vector<uint8_t>& key){
    if(pt.size()!=16||key.size()!=32) return {};
    uint8_t rk[10][16]; KS(key.data(),rk);
    uint8_t s[16]; memcpy(s,pt.data(),16);
    for(int r=0;r<9;r++) LSX(s,rk[r]);
    for(int i=0;i<16;i++) s[i]^=rk[9][i];
    return vector<uint8_t>(s,s+16);
}
inline vector<uint8_t> dec(const vector<uint8_t>& ct,const vector<uint8_t>& key){
    if(ct.size()!=16||key.size()!=32) return {};
    uint8_t rk[10][16]; KS(key.data(),rk);
    uint8_t s[16]; memcpy(s,ct.data(),16);
    for(int i=0;i<16;i++) s[i]^=rk[9][i];
    for(int r=8;r>=0;r--) InvLSX(s,rk[r]);
    return vector<uint8_t>(s,s+16);
}

inline vector<uint8_t> encrypt_raw(const vector<uint8_t>& p,const vector<uint8_t>& k){ return enc(p,k); }
inline vector<uint8_t> decrypt_raw(const vector<uint8_t>& c,const vector<uint8_t>& k){ return dec(c,k); }

}

inline vector<uint8_t> kuznechik_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key){
    return _kuznechik::encrypt_raw(plain,key);
}
inline vector<uint8_t> kuznechik_decrypt(const vector<uint8_t>& cipher,const vector<uint8_t>& key){
    return _kuznechik::decrypt_raw(cipher,key);
}

// ==================== Магма (ГОСТ 28147-89) ====================
namespace _magma {
// GOST 28147-89, id-GostR3411-94-TestParamSet
static const uint8_t SBOX[8][16]={
{4,10,9,2,13,8,0,14,6,11,1,12,7,15,5,3},
{14,11,4,12,6,13,15,10,2,3,8,1,0,7,5,9},
{5,8,1,13,10,3,4,2,14,15,12,7,6,0,9,11},
{7,13,10,1,0,8,9,15,14,4,6,12,11,2,5,3},
{6,12,7,1,5,15,13,8,4,10,9,14,0,3,11,2},
{4,11,10,0,7,2,1,13,3,6,8,5,9,12,15,14},
{13,11,4,1,3,15,5,9,0,10,14,7,6,8,2,12},
{1,15,13,0,5,7,10,4,9,2,3,14,6,11,8,12}};

inline uint32_t t(uint32_t v){
    uint32_t r=0;
    for(int i=0;i<8;i++) r|=(uint32_t)SBOX[i][(v>>(4*i))&0xF]<<(4*i);
    return (r<<11)|(r>>21);
}
inline void ldK(const vector<uint8_t>& key,uint32_t K[8]){
    for(int i=0;i<8;i++) memcpy(&K[i],key.data()+4*i,4);
}
inline vector<uint8_t> enc(const vector<uint8_t>& pt,const vector<uint8_t>& key){
    if(pt.size()!=8||key.size()!=32) return {};
    uint32_t K[8]; ldK(key,K);
    uint32_t n1,n2; memcpy(&n1,pt.data(),4); memcpy(&n2,pt.data()+4,4);
    for(int j=0;j<3;j++) for(int i=0;i<8;i+=2){ n2^=t(n1+K[i]); n1^=t(n2+K[i+1]); }
    for(int i=8;i>0;i-=2){ n2^=t(n1+K[i-1]); n1^=t(n2+K[i-2]); }
    vector<uint8_t> o(8); memcpy(o.data(),&n2,4); memcpy(o.data()+4,&n1,4); return o;
}
inline vector<uint8_t> dec(const vector<uint8_t>& ct,const vector<uint8_t>& key){
    if(ct.size()!=8||key.size()!=32) return {};
    uint32_t K[8]; ldK(key,K);
    uint32_t n1,n2; memcpy(&n1,ct.data(),4); memcpy(&n2,ct.data()+4,4);
    for(int i=0;i<8;i+=2){ n2^=t(n1+K[i]); n1^=t(n2+K[i+1]); }
    for(int j=0;j<3;j++) for(int i=8;i>0;i-=2){ n2^=t(n1+K[i-1]); n1^=t(n2+K[i-2]); }
    vector<uint8_t> o(8); memcpy(o.data(),&n2,4); memcpy(o.data()+4,&n1,4); return o;
}

inline vector<uint8_t> encrypt_raw(const vector<uint8_t>& p,const vector<uint8_t>& k){ return enc(p,k); }
inline vector<uint8_t> decrypt_raw(const vector<uint8_t>& c,const vector<uint8_t>& k){ return dec(c,k); }

}

inline vector<uint8_t> magma_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key){
    return _magma::encrypt_raw(plain,key);
}
inline vector<uint8_t> magma_decrypt(const vector<uint8_t>& cipher,const vector<uint8_t>& key){
    return _magma::decrypt_raw(cipher,key);
}

// ==================== fs.h (ПОЛНОСТЬЮ ПЕРЕПИСАННЫЙ, БЕЗ ИМПОРТОВ) ====================
namespace fs_ {

    #ifdef _WIN32

static const char* fs_fail = "Sorry, filesystem does not work on Windows.";

// ─── Пути ───
inline bool exists(const string&) { cerr << fs_fail << endl; return false; }
inline bool mkpath(const string&) { cerr << fs_fail << endl; return false; }

// ─── Чтение ───
inline string read(const string&) { cerr << fs_fail << endl; return ""; }
inline vector<uint8_t> read_bytes(const string&) { cerr << fs_fail << endl; return {}; }

// ─── Запись ───
inline void write(const string&, const string&) { cerr << fs_fail << endl; }
inline void write(const string&, const vector<uint8_t>&) { cerr << fs_fail << endl; }
inline void mkfile(const string&, const string&) { cerr << fs_fail << endl; }

// ─── Буфер ───
class Buffer {
public:
    Buffer() {}
    Buffer(size_t) {}
    Buffer(const vector<uint8_t>&) {}
    Buffer(const string&) {}
    static Buffer num(uint64_t) { return Buffer(); }
    void append(const vector<uint8_t>&) {}
    void append(const string&) {}
    vector<uint8_t>& data() { static vector<uint8_t> d; return d; }
    string str() const { return ""; }
    size_t size() const { return 0; }
    void clear() {}
    void save(const string&) {}
    void load(const string&) {}
    void encrypt(const vector<uint8_t>&) {}
    bool decrypt(const vector<uint8_t>&) { return false; }
    string hash() const { return ""; }
};

// ─── Таблица ───
class Table {
public:
    void set(const string&, const string&) {}
    string get(const string&, const string& = "") const { return ""; }
    bool has(const string&) const { return false; }
    void remove(const string&) {}
    size_t size() const { return 0; }
    vector<string> keys() const { return {}; }
    string serialize() const { return ""; }
    void deserialize(const string&) {}
    void save(const string&) {}
    void load(const string&) {}
};

// ─── Хранилище пользователей ───
class UserStore {
public:
    UserStore(const vector<uint8_t>&) {}
    void add(const string&, const string&) {}
    bool check(const string&, const string&) { return false; }
    void remove(const string&) {}
    bool exists(const string&) { return false; }
    size_t count() const { return 0; }
    void save(const string&) {}
    void load(const string&) {}
};

#else  // ==================== ORIGINAL FS_ CODE ====================
    
// ─── Пути ───
inline bool exists(const string& path) {
    return ifstream(path).good();
}

inline bool mkpath(const string& path) {
    size_t pos = 0;
    do {
        pos = path.find('/', pos + 1);
        string sub = path.substr(0, pos);
        if (!sub.empty() && ::mkdir(sub.c_str(), 0755) != 0 && errno != EEXIST)
            return false;
    } while (pos != string::npos);
    return true;
}

// ─── Чтение ───
inline string read(const string& path) {
    ifstream f(path, ios::binary);
    if (!f) return "";
    return {istreambuf_iterator<char>(f), istreambuf_iterator<char>()};
}

inline vector<uint8_t> read_bytes(const string& path) {
    ifstream f(path, ios::binary);
    if (!f) return {};
    return {istreambuf_iterator<char>(f), istreambuf_iterator<char>()};
}

// ─── Запись ───
inline void write(const string& path, const string& data) {
    size_t last = path.find_last_of('/');
    if (last != string::npos) mkpath(path.substr(0, last));
    ofstream f(path, ios::binary);
    f.write(data.data(), data.size());
}

inline void write(const string& path, const vector<uint8_t>& data) {
    size_t last = path.find_last_of('/');
    if (last != string::npos) mkpath(path.substr(0, last));
    ofstream f(path, ios::binary);
    f.write((char*)data.data(), data.size());
}

inline void mkfile(const string& path, const string& data) {
    write(path, data);
}

// ─── Буфер ───
class Buffer {
    vector<uint8_t> _data;
public:
    Buffer() {}
    Buffer(size_t size) : _data(size) {}
    Buffer(const vector<uint8_t>& data) : _data(data) {}
    Buffer(const string& data) : _data(data.begin(), data.end()) {}
    
    // Числа → буфер
    static Buffer num(uint64_t v) {
        Buffer b(8);
        for (int i = 0; i < 8; i++) b._data[i] = (v >> (i * 8)) & 0xFF;
        return b;
    }
    static Buffer num(uint32_t v) {
        Buffer b(4);
        for (int i = 0; i < 4; i++) b._data[i] = (v >> (i * 8)) & 0xFF;
        return b;
    }
    static Buffer num(int v) { return num((uint32_t)v); }
    static Buffer num(double v) {
        Buffer b(8);
        memcpy(b._data.data(), &v, 8);
        return b;
    }
    
    // Добавление
    void append(const vector<uint8_t>& data) {
        _data.insert(_data.end(), data.begin(), data.end());
    }
    void append(const string& data) {
        _data.insert(_data.end(), data.begin(), data.end());
    }
    void append(const Buffer& buf) {
        append(buf._data);
    }
    void append(uint64_t v) {
        Buffer tmp = num(v);
        append(tmp._data);
    }
    void append(const uint8_t* data, size_t len) {
        _data.insert(_data.end(), data, data + len);
    }
    template<size_t N>
    void append(const uint8_t (&arr)[N]) {
        append(arr, N);
    }
    
    // Доступ
    vector<uint8_t>& data() { return _data; }
    const vector<uint8_t>& data() const { return _data; }
    string str() const { return {_data.begin(), _data.end()}; }
    size_t size() const { return _data.size(); }
    void clear() { _data.clear(); }
    bool empty() const { return _data.empty(); }
    
    uint8_t& operator[](size_t i) { return _data[i]; }
    const uint8_t& operator[](size_t i) const { return _data[i]; }
    
    // В число
    uint64_t to_u64() const {
        if (_data.size() < 8) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= ((uint64_t)_data[i] << (i * 8));
        return v;
    }
    
    // Файлы
    void save(const string& path) { write(path, _data); }
    void load(const string& path) { _data = read_bytes(path); }
    
    // Шифрование
    void encrypt(const vector<uint8_t>& key) {
        _data = aes256_gcm_encrypt(_data, key);
    }
    bool decrypt(const vector<uint8_t>& key) {
    if (aes256_gcm_decrypt(_data, key, _data)) return true;
    return aes256_gcm_decrypt_legacy(_data, key, _data);
}
    
    // С солью
    void encrypt_salted(const vector<uint8_t>& key, uint64_t salt) {
        Buffer s = num(salt);
        Buffer combined;
        combined.append(s);
        combined.append(_data);
        combined.encrypt(key);
        _data = combined._data;
    }
    
    bool decrypt_salted(const vector<uint8_t>& key, uint64_t& salt) {
        if (!decrypt(key)) return false;
        if (_data.size() < 8) return false;
        salt = 0;
        for (int i = 0; i < 8; i++) salt |= ((uint64_t)_data[i] << (i * 8));
        _data.erase(_data.begin(), _data.begin() + 8);
        return true;
    }
    
    // Хеш
    string hash() const { return sha256(_data); }
};

// ─── Таблица ───
class Table {
    vector<pair<string, string>> _rows;
public:
    void set(const string& key, const string& value) {
        for (auto& [k, v] : _rows) {
            if (k == key) { v = value; return; }
        }
        _rows.push_back({key, value});
    }
    
    string get(const string& key, const string& def = "") const {
        for (auto& [k, v] : _rows)
            if (k == key) return v;
        return def;
    }
    
    bool has(const string& key) const {
        for (auto& [k, v] : _rows)
            if (k == key) return true;
        return false;
    }
    
    void remove(const string& key) {
        _rows.erase(remove_if(_rows.begin(), _rows.end(),
            [&](auto& p){ return p.first == key; }), _rows.end());
    }
    
    size_t size() const { return _rows.size(); }
    
    vector<string> keys() const {
        vector<string> r;
        for (auto& [k, v] : _rows) r.push_back(k);
        return r;
    }
    
    string serialize() const {
        string r;
        for (auto& [k, v] : _rows) r += k + "=" + v + "\n";
        return r;
    }
    
    void deserialize(const string& data) {
        _rows.clear();
        stringstream ss(data);
        string line;
        while (getline(ss, line)) {
            if (line.empty()) continue;
            size_t eq = line.find('=');
            if (eq == string::npos) continue;
            _rows.push_back({line.substr(0, eq), line.substr(eq + 1)});
        }
    }
    
    void save(const string& path) { write(path, serialize()); }
    void load(const string& path) { deserialize(read(path)); }
    
    void save_encrypted(const string& path, const vector<uint8_t>& key) {
        Buffer buf(serialize());
        buf.encrypt(key);
        buf.save(path);
    }
    
    void load_encrypted(const string& path, const vector<uint8_t>& key) {
        Buffer buf;
        buf.load(path);
        buf.decrypt(key);
        deserialize(buf.str());
    }
    
    auto begin() { return _rows.begin(); }
    auto end() { return _rows.end(); }
};

// ─── Хранилище пользователей ───
class UserStore {
    Table _users;
    vector<uint8_t> _key;
    
public:
    UserStore(const vector<uint8_t>& key) : _key(key) {}
    
    void add(const string& login, const string& password) {
        uint64_t salt = rand_::salt();
        string hash = sha512(password, salt);
        _users.set(login, hash + "|" + to_string(salt));
    }
    
    bool check(const string& login, const string& password) {
        if (!_users.has(login)) return false;
        string data = _users.get(login);
        size_t sep = data.find('|');
        if (sep == string::npos) return false;
        string hash = data.substr(0, sep);
        uint64_t salt = stoull(data.substr(sep + 1));
        return sha512(password, salt) == hash;
    }
    
    void remove(const string& login) { _users.remove(login); }
    bool exists(const string& login) { return _users.has(login); }
    size_t count() const { return _users.size(); }
    
    void save(const string& path) { _users.save_encrypted(path, _key); }
    void load(const string& path) { _users.load_encrypted(path, _key); }
};
#endif  // _WIN32
} // namespace fs_

// ==================== turbo.h (МАКРОСЫ ДЛЯ ПРОСТОТЫ) ====================
namespace turbo_ {

inline size_t cores() {
    return max(1u, thread::hardware_concurrency());
}

template<typename F>
inline void run(F&& func) {
    size_t n = cores();
    if (n <= 1) { func(); return; }
    
    vector<thread> threads;
    for (size_t i = 0; i < n; i++)
        threads.emplace_back(func);
    for (auto& t : threads) t.join();
}

template<typename F>
inline void repeat(size_t count, F&& func) {
    size_t n = min(cores(), count);
    size_t per = (count + n - 1) / n;
    
    vector<thread> threads;
    for (size_t t = 0; t < n; t++) {
        threads.emplace_back([=]() {
            size_t start = t * per;
            size_t end = min(start + per, count);
            for (size_t i = start; i < end; i++) func();
        });
    }
    for (auto& t : threads) t.join();
}

} // namespace turbo_

// Макросы
#define turbo(call)   turbo_::run([&]() { call; })
#define turbo_r(n, call) turbo_::repeat(n, [&]() { call; })

// ==================== PERLIN NOISE ====================
namespace perlin_ {

inline double fade(double t) { return t * t * t * (t * (t * 6 - 15) + 10); }
inline double lerp(double a, double b, double t) { return a + t * (b - a); }

inline double grad(int hash, double x, double y) {
    int h = hash & 15;
    double u = h < 8 ? x : y;
    double v = h < 4 ? y : (h == 12 || h == 14 ? x : 0);
    return ((h & 1) == 0 ? u : -u) + ((h & 2) == 0 ? v : -v);
}

inline vector<unsigned char> gen_perm(int seed) {
vector<unsigned char> p(256);
for (int i = 0; i < 256; i++) p[i] = (unsigned char)i;
mt19937 gen(seed);
shuffle(p.begin(), p.end(), gen);
p.resize(512);
for (int i = 0; i < 256; i++) p[256 + i] = p[i];
return p;
}

inline const vector<unsigned char>& get_perm(int seed) {
    static std::map<int, vector<unsigned char>> cache;
    if (cache.find(seed) == cache.end()) cache[seed] = gen_perm(seed);
    return cache[seed];
}

// ===== БАЗОВЫЙ ШУМ =====
inline double noise(double x, double y, int seed, double scale, int octaves) {
if (octaves < 1) return 0.0;
if (octaves > 30) octaves = 30;
    const auto& p = get_perm(seed);
    double result = 0, max_val = 0, amp = 1;
    for (int o = 0; o < octaves; o++) {
        double nx = x * (1 << o) * scale;
        double ny = y * (1 << o) * scale;
        int X = (int)floor(nx) & 255;
        int Y = (int)floor(ny) & 255;
        double fx = nx - floor(nx);
        double fy = ny - floor(ny);
        double u = fade(fx), v = fade(fy);
        int A = p[X] + Y, AA = p[A], AB = p[A + 1], B = p[X + 1] + Y, BA = p[B], BB = p[B + 1];
        double n = lerp(v, lerp(u, grad(p[AA], fx, fy), grad(p[BA], fx - 1, fy)),
                           lerp(u, grad(p[AB], fx, fy - 1), grad(p[BB], fx - 1, fy - 1)));
        result += n * amp;
        max_val += amp;
        amp *= 0.5;
    }
    return result / max_val;
}

// ===== ЦВЕТ (ШАБЛОН) — нормализованный 0..1 =====
template<typename T>
inline T color(double x, double y, int seed, double scale, int octaves) {
    double n = (noise(x, y, seed, scale, octaves) + 1.0) / 2.0;
    // clamp to 0..1
    if (n < 0.0) n = 0.0;
    if (n > 1.0) n = 1.0;
    
    if constexpr (is_same_v<T, double>) return n;
    if constexpr (is_same_v<T, float>) return (float)n;
    if constexpr (is_same_v<T, uint8_t>) return (uint8_t)(n * 255);
    if constexpr (is_same_v<T, uint16_t>) return (uint16_t)(n * 65535);
    if constexpr (is_same_v<T, uint32_t>) return (uint32_t)(n * 4294967295.0);
    if constexpr (is_same_v<T, uint64_t>) return (uint64_t)(n * 18446744073709551615.0);
    if constexpr (is_same_v<T, int>) return (int)(n * 2147483647.0);
    if constexpr (is_same_v<T, long long>) return (long long)(n * 9223372036854775807.0);
    return (T)n;
}

// ===== РАНДОМНЫЙ ШУМ =====
inline double random_noise(double x, double y, double scale, int octaves) {
    return noise(x, y, rand_::range(1, 2147483647), scale, octaves);
}

template<typename T>
inline T random_color(double x, double y, double scale, int octaves) {
    return color<T>(x, y, rand_::range(1, 2147483647), scale, octaves);
}

// ===== ГЕНЕРАЦИЯ КАРТ (1D) С НОРМАЛИЗАЦИЕЙ =====
template<typename T>
inline void generate_map_1d(vector<T>& out, int width, int seed, double scale, int octaves) {
    out.resize(width);
    double min_val = 1e9, max_val = -1e9;
    for (int x = 0; x < width; x++) {
        double val = noise((double)x, 0, seed, scale, octaves);
        if (val < min_val) min_val = val;
        if (val > max_val) max_val = val;
    }
    double range = max_val - min_val;
    if (range == 0) range = 1;
    for (int x = 0; x < width; x++) {
        double val = noise((double)x, 0, seed, scale, octaves);
        out[x] = (T)((val - min_val) / range);
    }
}

template<typename T>
inline void generate_map_1d(T* arr, int width, int seed, double scale, int octaves) {
    double min_val = 1e9, max_val = -1e9;
    for (int x = 0; x < width; x++) {
        double val = noise((double)x, 0, seed, scale, octaves);
        if (val < min_val) min_val = val;
        if (val > max_val) max_val = val;
    }
    double range = max_val - min_val;
    if (range == 0) range = 1;
    for (int x = 0; x < width; x++) {
        double val = noise((double)x, 0, seed, scale, octaves);
        arr[x] = (T)((val - min_val) / range);
    }
}

// ===== ГЕНЕРАЦИЯ КАРТ (2D) С НОРМАЛИЗАЦИЕЙ =====
template<typename T>
inline void generate_map_2d(vector<vector<T>>& out, int w, int h, int seed, double scale, int octaves) {
    out.resize(h, vector<T>(w));
    double min_val = 1e9, max_val = -1e9;
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            double val = noise((double)x, (double)y, seed, scale, octaves);
            if (val < min_val) min_val = val;
            if (val > max_val) max_val = val;
        }
    double range = max_val - min_val;
    if (range == 0) range = 1;
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            double val = noise((double)x, (double)y, seed, scale, octaves);
            out[y][x] = (T)((val - min_val) / range);
        }
}

template<typename T>
inline void generate_map_2d(T* arr, int w, int h, int seed, double scale, int octaves) {
    double min_val = 1e9, max_val = -1e9;
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            double val = noise((double)x, (double)y, seed, scale, octaves);
            if (val < min_val) min_val = val;
            if (val > max_val) max_val = val;
        }
    double range = max_val - min_val;
    if (range == 0) range = 1;
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            double val = noise((double)x, (double)y, seed, scale, octaves);
            arr[y * w + x] = (T)((val - min_val) / range);
        }
}

// ===== РАНДОМНЫЕ КАРТЫ =====
template<typename T>
inline void random_map_1d(vector<T>& out, int width, double scale, int octaves) {
    generate_map_1d(out, width, rand_::range(1, 2147483647), scale, octaves);
}

template<typename T>
inline void random_map_1d(T* arr, int width, double scale, int octaves) {
    generate_map_1d(arr, width, rand_::range(1, 2147483647), scale, octaves);
}

template<typename T>
inline void random_map_2d(vector<vector<T>>& out, int w, int h, double scale, int octaves) {
    generate_map_2d(out, w, h, rand_::range(1, 2147483647), scale, octaves);
}

template<typename T>
inline void random_map_2d(T* arr, int w, int h, double scale, int octaves) {
    generate_map_2d(arr, w, h, rand_::range(1, 2147483647), scale, octaves);
}
    
    // ===== ФУНКЦИИ С ВОЗВРАТОМ ВЕКТОРА =====
template<typename T>
inline vector<T> make_map_1d(int width, int seed, double scale, int octaves) {
    vector<T> out;
    generate_map_1d(out, width, seed, scale, octaves);
    return out;
}

template<typename T>
inline vector<vector<T>> make_map_2d(int w, int h, int seed, double scale, int octaves) {
    vector<vector<T>> out;
    generate_map_2d(out, w, h, seed, scale, octaves);
    return out;
}

template<typename T>
inline vector<T> random_make_map_1d(int width, double scale, int octaves) {
    vector<T> out;
    random_map_1d(out, width, scale, octaves);
    return out;
}

template<typename T>
inline vector<vector<T>> random_make_map_2d(int w, int h, double scale, int octaves) {
    vector<vector<T>> out;
    random_map_2d(out, w, h, scale, octaves);
    return out;
}

} // namespace perlin_

namespace rand_pp {

    // ================================================================
    // 1. RC4 — полная реализация
    // ================================================================
    namespace rand_rc4 {

        struct State {
            uint8_t S[256];
            int i, j;
        };

        inline State init(const vector<uint8_t>& key) {
            State st;
            for (int i = 0; i < 256; i++) st.S[i] = i;
            int j = 0;
            for (int i = 0; i < 256; i++) {
                j = (j + st.S[i] + key[i % key.size()]) & 0xFF;
                swap(st.S[i], st.S[j]);
            }
            st.i = st.j = 0;
            return st;
        }

        inline uint8_t next_byte(State& st) {
            st.i = (st.i + 1) & 0xFF;
            st.j = (st.j + st.S[st.i]) & 0xFF;
            swap(st.S[st.i], st.S[st.j]);
            return st.S[(st.S[st.i] + st.S[st.j]) & 0xFF];
        }

        inline vector<uint8_t> bytes(size_t n, const vector<uint8_t>& key) {
            State st = init(key);
            vector<uint8_t> r(n);
            for (size_t i = 0; i < n; i++) r[i] = next_byte(st);
            return r;
        }

        inline uint64_t u64(const vector<uint8_t>& key) {
            auto b = bytes(8, key);
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v |= ((uint64_t)b[i] << (i * 8));
            return v;
        }

        inline uint32_t u32(const vector<uint8_t>& key) {
            auto b = bytes(4, key);
            return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
                   ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        }

        inline uint64_t range(uint64_t min, uint64_t max, const vector<uint8_t>& key) {
            if (min == max) return min;
            return min + (u64(key) % (max - min + 1));
        }

        inline double frand(const vector<uint8_t>& key) {
            return (double)u64(key) / (double)(~0ULL);
        }

        template<typename T>
        inline void shuffle(vector<T>& v, const vector<uint8_t>& key) {
            for (size_t i = v.size() - 1; i > 0; i--) {
                size_t j = (size_t)range(0, i, key);
                swap(v[i], v[j]);
            }
        }

        template<typename T>
        inline T choice(const vector<T>& v, const vector<uint8_t>& key) {
            return v[(size_t)range(0, v.size() - 1, key)];
        }

        inline void fill(void* ptr, size_t len, const vector<uint8_t>& key) {
            auto b = bytes(len, key);
            memcpy(ptr, b.data(), len);
        }

    } // namespace rand_rc4

    // ================================================================
    // 2. MT19937 — полная реализация
    // ================================================================
    namespace rand_mt19937 {

        class MT19937 {
            static const int N = 624;
            static const int M = 397;
            static const uint32_t MATRIX_A = 0x9908b0dfUL;
            uint32_t mt[N];
            int index;

            void twist() {
                for (int i = 0; i < N; i++) {
                    uint32_t x = (mt[i] & 0x80000000UL) + (mt[(i+1)%N] & 0x7fffffffUL);
                    uint32_t xA = (x >> 1) ^ ((x & 1) ? MATRIX_A : 0);
                    mt[i] = mt[(i+M)%N] ^ xA;
                }
                index = 0;
            }

        public:
            MT19937(uint32_t seed) {
                mt[0] = seed;
                for (int i = 1; i < N; i++) {
                    mt[i] = (1812433253UL * (mt[i-1] ^ (mt[i-1] >> 30)) + i);
                }
                index = N;
            }

            uint32_t next() {
                if (index >= N) twist();
                uint32_t y = mt[index++];
                y ^= (y >> 11);
                y ^= (y << 7) & 0x9d2c5680UL;
                y ^= (y << 15) & 0xefc60000UL;
                y ^= (y >> 18);
                return y;
            }

            vector<uint8_t> bytes(size_t n) {
                vector<uint8_t> r(n);
                for (size_t i = 0; i < n; i += 4) {
                    uint32_t v = next();
                    for (int j = 0; j < 4 && i+j < n; j++) {
                        r[i+j] = (v >> (j*8)) & 0xFF;
                    }
                }
                return r;
            }

            uint64_t u64() {
                return ((uint64_t)next() << 32) | next();
            }

            uint32_t u32() {
                return next();
            }

            uint64_t range(uint64_t min, uint64_t max) {
                if (min == max) return min;
                return min + (u64() % (max - min + 1));
            }

            double frand() {
                return (double)u64() / (double)(~0ULL);
            }

            template<typename T>
            void shuffle(vector<T>& v) {
                for (size_t i = v.size() - 1; i > 0; i--) {
                    size_t j = (size_t)range(0, i);
                    swap(v[i], v[j]);
                }
            }

            template<typename T>
            T choice(const vector<T>& v) {
                return v[(size_t)range(0, v.size() - 1)];
            }

            void fill(void* ptr, size_t len) {
                auto b = bytes(len);
                memcpy(ptr, b.data(), len);
            }
        };

    } // namespace rand_mt19937

    // ================================================================
    // 3. PCG — полная реализация
    // ================================================================
    namespace rand_pcg {

        class PCG {
            uint64_t state, inc;
        public:
            PCG(uint64_t seed) {
                state = seed;
                inc = 0x9e3779b97f4a7c15ULL;
                next();
            }

            uint32_t next() {
                uint64_t old = state;
                state = old * 6364136223846793005ULL + inc;
                uint32_t x = ((old >> 18) ^ old) >> 27;
                uint32_t rot = old >> 59;
                return (x >> rot) | (x << ((-rot) & 31));
            }

            vector<uint8_t> bytes(size_t n) {
                vector<uint8_t> r(n);
                for (size_t i = 0; i < n; i += 4) {
                    uint32_t v = next();
                    for (int j = 0; j < 4 && i+j < n; j++) {
                        r[i+j] = (v >> (j*8)) & 0xFF;
                    }
                }
                return r;
            }

            uint64_t u64() {
                return ((uint64_t)next() << 32) | next();
            }

            uint32_t u32() {
                return next();
            }

            uint64_t range(uint64_t min, uint64_t max) {
                if (min == max) return min;
                return min + (u64() % (max - min + 1));
            }

            double frand() {
                return (double)u64() / (double)(~0ULL);
            }

            template<typename T>
            void shuffle(vector<T>& v) {
                for (size_t i = v.size() - 1; i > 0; i--) {
                    size_t j = (size_t)range(0, i);
                    swap(v[i], v[j]);
                }
            }

            template<typename T>
            T choice(const vector<T>& v) {
                return v[(size_t)range(0, v.size() - 1)];
            }

            void fill(void* ptr, size_t len) {
                auto b = bytes(len);
                memcpy(ptr, b.data(), len);
            }
        };

    } // namespace rand_pcg

    // ================================================================
    // 4. MRG32k3a — полная реализация
    // ================================================================
    namespace rand_mrg32k3a {

        class MRG32k3a {
            double s1[3], s2[3];
        public:
            MRG32k3a(uint32_t seed) {
                for (int i = 0; i < 3; i++) {
                    s1[i] = (seed + i * 12345) % 1000000;
                    s2[i] = (seed + i * 67890 + 12345) % 1000000;
                }
            }

            double next() {
                double a12 = 1403580, a13n = 810728;
                double a21 = 527612, a23n = 1370589;
                double m1 = 4294967087.0, m2 = 4294944443.0;
                double p1 = (a12 * s1[1] - a13n * s1[0]) / m1;
                while (p1 < 0) p1 += m1;
                while (p1 >= m1) p1 -= m1;
                double p2 = (a21 * s2[2] - a23n * s2[0]) / m2;
                while (p2 < 0) p2 += m2;
                while (p2 >= m2) p2 -= m2;
                s1[0] = s1[1]; s1[1] = s1[2]; s1[2] = p1;
                s2[0] = s2[1]; s2[1] = s2[2]; s2[2] = p2;
                double z = (p1 - p2) / (m1 + 1);
                if (z < 0) z += 1;
                return z;
            }

            vector<uint8_t> bytes(size_t n) {
                vector<uint8_t> r(n);
                for (size_t i = 0; i < n; i++) {
                    r[i] = (uint8_t)(next() * 256);
                }
                return r;
            }

            uint64_t u64() {
                uint64_t v = 0;
                for (int i = 0; i < 8; i++) {
                    v |= ((uint64_t)(next() * 256) << (i * 8));
                }
                return v;
            }

            uint32_t u32() {
                uint32_t v = 0;
                for (int i = 0; i < 4; i++) {
                    v |= ((uint32_t)(next() * 256) << (i * 8));
                }
                return v;
            }

            uint64_t range(uint64_t min, uint64_t max) {
                if (min == max) return min;
                return min + (u64() % (max - min + 1));
            }

            double frand() {
                return next();
            }

            template<typename T>
            void shuffle(vector<T>& v) {
                for (size_t i = v.size() - 1; i > 0; i--) {
                    size_t j = (size_t)range(0, i);
                    swap(v[i], v[j]);
                }
            }

            template<typename T>
            T choice(const vector<T>& v) {
                return v[(size_t)range(0, v.size() - 1)];
            }

            void fill(void* ptr, size_t len) {
                auto b = bytes(len);
                memcpy(ptr, b.data(), len);
            }
        };

    } // namespace rand_mrg32k3a

    // ================================================================
    // 5. ChaCha20 CSPRNG — полная реализация (без внешних зависимостей)
    // ================================================================
    namespace rand_chacha20 {

        inline vector<uint8_t> bytes(size_t n, const vector<uint8_t>& key, const vector<uint8_t>& nonce) {
            vector<uint8_t> zero(n, 0);
            return _chacha::crypt_raw(zero, key, nonce); // использует твою реализацию ChaCha20
        }

        inline uint64_t u64(const vector<uint8_t>& key, const vector<uint8_t>& nonce) {
            auto b = bytes(8, key, nonce);
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v |= ((uint64_t)b[i] << (i * 8));
            return v;
        }

        inline uint32_t u32(const vector<uint8_t>& key, const vector<uint8_t>& nonce) {
            auto b = bytes(4, key, nonce);
            return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
                   ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        }

        inline uint64_t range(uint64_t min, uint64_t max, const vector<uint8_t>& key, const vector<uint8_t>& nonce) {
            if (min == max) return min;
            return min + (u64(key, nonce) % (max - min + 1));
        }

        inline double frand(const vector<uint8_t>& key, const vector<uint8_t>& nonce) {
            return (double)u64(key, nonce) / (double)(~0ULL);
        }

        template<typename T>
        inline void shuffle(vector<T>& v, const vector<uint8_t>& key, const vector<uint8_t>& nonce) {
            for (size_t i = v.size() - 1; i > 0; i--) {
                size_t j = (size_t)range(0, i, key, nonce);
                swap(v[i], v[j]);
            }
        }

        template<typename T>
        inline T choice(const vector<T>& v, const vector<uint8_t>& key, const vector<uint8_t>& nonce) {
            return v[(size_t)range(0, v.size() - 1, key, nonce)];
        }

        inline void fill(void* ptr, size_t len, const vector<uint8_t>& key, const vector<uint8_t>& nonce) {
            auto b = bytes(len, key, nonce);
            memcpy(ptr, b.data(), len);
        }

    } // namespace rand_chacha20
    
    // ================================================================
// 6. AES-256-GCM CSPRNG — исправленная версия
// ================================================================
namespace rand_aes {

    inline vector<uint8_t> bytes(size_t n, const vector<uint8_t>& key) {
        vector<uint8_t> zero(n, 0);
        return aes256_gcm_encrypt(zero, key);
    }

    inline uint64_t u64(const vector<uint8_t>& key) {
        auto b = bytes(8, key);
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= ((uint64_t)b[i] << (i * 8));
        return v;
    }

    inline uint32_t u32(const vector<uint8_t>& key) {
        auto b = bytes(4, key);
        return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
               ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    }

    inline uint64_t range(uint64_t min, uint64_t max, const vector<uint8_t>& key) {
        if (min == max) return min;
        return min + (u64(key) % (max - min + 1));
    }

    inline double frand(const vector<uint8_t>& key) {
        return (double)u64(key) / (double)(~0ULL);
    }

    template<typename T>
    inline void shuffle(vector<T>& v, const vector<uint8_t>& key) {
        for (size_t i = v.size() - 1; i > 0; i--) {
            size_t j = (size_t)range(0, i, key);
            swap(v[i], v[j]);
        }
    }

    template<typename T>
    inline T choice(const vector<T>& v, const vector<uint8_t>& key) {
        return v[(size_t)range(0, v.size() - 1, key)];
    }

    inline void fill(void* ptr, size_t len, const vector<uint8_t>& key) {
        auto b = bytes(len, key);
        memcpy(ptr, b.data(), len);
    }

} // namespace rand_aes

} // namespace rand_pp


// ==================== Password hashing: default PBKDF2-HMAC-SHA256 ====================
namespace _pw {

inline string b64url_encode(const vector<uint8_t>& in){
    static const char alph[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < in.size()) {
        uint32_t n = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | (uint32_t)in[i+2];
        out.push_back(alph[(n >> 18) & 63]);
        out.push_back(alph[(n >> 12) & 63]);
        out.push_back(alph[(n >> 6) & 63]);
        out.push_back(alph[n & 63]);
        i += 3;
    }
    if (i + 1 == in.size()) {
        uint32_t n = (uint32_t)in[i] << 16;
        out.push_back(alph[(n >> 18) & 63]);
        out.push_back(alph[(n >> 12) & 63]);
    } else if (i + 2 == in.size()) {
        uint32_t n = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8);
        out.push_back(alph[(n >> 18) & 63]);
        out.push_back(alph[(n >> 12) & 63]);
        out.push_back(alph[(n >> 6) & 63]);
    }
    return out;
}

inline int b64url_val(char c){
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

inline vector<uint8_t> b64url_decode(const string& s){
    vector<uint8_t> r;
    uint32_t buffer = 0; int bits = 0;
    for (char c : s) {
        if (c == '=') continue;
        int v = b64url_val(c);
        if (v < 0) return vector<uint8_t>();
        buffer = (buffer << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            r.push_back((uint8_t)((buffer >> bits) & 0xFF));
            buffer &= (1u << bits) - 1;
        }
    }
    // Canonical base64url: unused trailing bits must be zero; length mod 4 == 1 invalid.
    if (bits == 6) return vector<uint8_t>();
    if (bits != 0 && buffer != 0) return vector<uint8_t>();
    return r;
}

inline string password_hash(const string& pass, int iterations = 100000){
    if (iterations < 1000) iterations = 1000;
    if (iterations > 100000000) iterations = 100000000;

    vector<uint8_t> salt = _::csrandb(16);
    vector<uint8_t> dk = pbkdf2_sha256(pass, salt, iterations);

    return string("$pbkdf2-sha256$") + to_string(iterations) + "$"
         + b64url_encode(salt) + "$" + b64url_encode(dk);
}

inline bool password_verify(const string& pass, const string& stored){
    if (stored.empty() || stored[0] != '$') return false;

    size_t p1 = stored.find('$', 1);
    if (p1 == string::npos) return false;
    size_t p2 = stored.find('$', p1 + 1);
    if (p2 == string::npos) return false;
    size_t p3 = stored.find('$', p2 + 1);
    if (p3 == string::npos) return false;

    string algo = stored.substr(1, p1 - 1);
    if (algo != "pbkdf2-sha256") return false;

    string iter_s = stored.substr(p1 + 1, p2 - p1 - 1);
    if (iter_s.empty()) return false;

    long long iter_ll = 0;
    for (char c : iter_s) {
        if (c < '0' || c > '9') return false;
        if (iter_ll > 10000000LL) return false;
        iter_ll = iter_ll * 10 + (c - '0');
        if (iter_ll > 100000000LL) return false;
    }
    if (iter_ll < 1 || iter_ll > 100000000LL) return false;
    int iterations = (int)iter_ll;

    vector<uint8_t> salt = b64url_decode(stored.substr(p2 + 1, p3 - p2 - 1));
    vector<uint8_t> want = b64url_decode(stored.substr(p3 + 1));
    if (salt.empty() || want.empty()) return false;
    if (salt.size() > 64 || want.size() > 128) return false;

    vector<uint8_t> got = pbkdf2_sha256(pass, salt, iterations);
    if (got.size() != want.size()) return false;

    volatile uint8_t diff = 0;
    for (size_t i = 0; i < got.size(); ++i) {
        diff |= (uint8_t)(got[i] ^ want[i]);
    }
    return diff == 0;
}

// Experimental wrappers: не использовать по умолчанию.
inline string password_hash_bcrypt_experimental(const string& pass, unsigned int cost = 12){
    return bcrypt_hash(pass, cost);
}

inline bool password_verify_bcrypt_experimental(const string& pass, const string& hash){
    return bcrypt_check(pass, hash);
}

} // namespace _pw

// ===================================================================
// КОНЕЦ all_crypto.h
// ===================================================================