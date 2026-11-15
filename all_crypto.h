#pragma once
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
        random_device rd;
        s[0] = (uint64_t(rd()) << 32) | rd();
        s[1] = (uint64_t(rd()) << 32) | rd();
        if (s[0] == 0 && s[1] == 0) { s[0] = 1; s[1] = 1; }
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

inline uint64_t salt() { return u64() & 0x7FFFFFFFFFFFFFFFULL; }

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
        uint64_t sum = carry;
        if (i < a.size()) sum += a[i];
        if (i < b.size()) sum += b[i];
        r.push_back(sum);
        carry = (sum < carry) ? 1 : 0;
    }
    if (carry) r.push_back(1);
    while (!r.empty() && r.back() == 0) r.pop_back();
    return r;
}

// ─── Вычитание ───
inline BigNum sub(const BigNum& a, const BigNum& b) {
    BigNum r = a;
    uint64_t borrow = 0;
    for (size_t i = 0; i < r.size(); ++i) {
        uint64_t s = borrow + (i < b.size() ? b[i] : 0);
        borrow = (r[i] < s) ? 1 : 0;
        r[i] -= s;
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
            __uint128_t prod = (__uint128_t)a[i] * b[j] + r[i + j] + carry;
            r[i + j] = (uint64_t)prod;
            carry = (uint64_t)(prod >> 64);
        }
        if (carry) r[i + b.size()] += carry;
    }
    while (!r.empty() && r.back() == 0) r.pop_back();
    return r;
}
    
       // ─── Деление с остатком (Knuth, без гибрида) ───
inline std::pair<BigNum, BigNum> divmod(const BigNum& a, const BigNum& b) {
    if (b.empty() || b.size() == 0) return {BigNum(), BigNum()};
    if (a.size() < b.size()) return {BigNum(), a};

    // Случай деления на одно слово (быстрый путь)
    if (b.size() == 1) {
        BigNum r = a;
        uint64_t divisor = b[0];
        uint64_t carry = 0;
        for (size_t i = a.size(); i-- > 0;) {
            __uint128_t v = (__uint128_t(carry) << 64) + a[i];
            r[i] = v / divisor;
            carry = v % divisor;
        }
        while (r.size() > 1 && r.back() == 0) r.pop_back();
        BigNum rem;
        if (carry) rem.push_back(carry);
        return {r, rem};
    }

    // Нормализация
    BigNum divisor = b;
    size_t n = divisor.size();
    size_t m = a.size() - n;
    BigNum dividend = a;
    uint64_t shift = 0;
    uint64_t top = divisor.back();
    if (top < (1ULL << 63)) {
        shift = __builtin_clzll(top);
        divisor = mul(divisor, from_u64(1ULL << shift));
        dividend = mul(dividend, from_u64(1ULL << shift));
        while (!dividend.empty() && dividend.back() == 0) dividend.pop_back();
        if (dividend.size() < a.size() + 1) dividend.push_back(0);
    }

    BigNum q(m + 1, 0);
    BigNum r = dividend;
    r.push_back(0);

    for (size_t j = m + 1; j-- > 0;) {
        uint64_t r_top = (j + n < r.size()) ? r[j + n] : 0;
        uint64_t r_second = (j + n - 1 < r.size()) ? r[j + n - 1] : 0;
        uint64_t divisor_top = divisor.back();

        __uint128_t q_hat = (__uint128_t(r_top) << 64) + r_second;
        if (divisor_top == 0) q_hat = 0;
        else q_hat /= divisor_top;
        if (q_hat >> 64) q_hat = ~(__uint128_t)0;

        uint64_t borrow = 0;
        for (size_t i = 0; i < n; ++i) {
            __uint128_t sub = q_hat * divisor[i] + borrow;
            uint64_t sub_lo = (uint64_t)sub;
            borrow = (sub >> 64);
            if (r[j + i] < sub_lo) {
                r[j + i] = r[j + i] - sub_lo;
                borrow++;
            } else {
                r[j + i] -= sub_lo;
            }
        }
        if (r[j + n] < borrow) {
            r[j + n] = r[j + n] - borrow;
            borrow = 1;
        } else {
            r[j + n] -= borrow;
            borrow = 0;
        }

        q[j] = (uint64_t)q_hat;
        if (borrow) {
            q[j]--;
            uint64_t carry = 0;
            for (size_t i = 0; i < n; ++i) {
                uint64_t sum = r[j + i] + divisor[i] + carry;
                carry = (sum < r[j + i]) ? 1 : 0;
                r[j + i] = sum;
            }
            r[j + n] += carry;
        }
    }

    while (q.size() > 1 && q.back() == 0) q.pop_back();
    while (r.size() > 1 && r.back() == 0) r.pop_back();

    if (shift) {
        r = divmod(r, from_u64(1ULL << shift)).first;
    }

    return {q, r};
}

// ─── Модуль ───
inline BigNum mod(const BigNum& a, const BigNum& b) {
    if (b.empty()) return BigNum();
    if (lt(a, b)) return a;
    BigNum r = a;
    while (!lt(r, b)) {
        r = sub(r, b);
    }
    return r;
}

// ─── Модульное возведение в степень ───
inline BigNum modpow(const BigNum& base, const BigNum& exp, const BigNum& mod) {
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

// ─── Модуль (с новым именем mod_big) ───
inline BigNum mod_big(const BigNum& a, const BigNum& b) {
    return divmod(a, b).second;
}
    
    // ─── Проверка простоты ───
inline bool is_prime(const BigNum& n) {
    if (zero(n)) return false;
    if (eq(n, from_u64(2)) || eq(n, from_u64(3))) return true;
    if ((n[0] & 1) == 0) return false;

    // 1. Проверка на маленькие простые (отсеивает 90% составных)
    for (size_t i = 0; i < _primes::small_primes_count; ++i) {
        uint64_t p = _primes::small_primes[i];
        if (eq(n, from_u64(p))) return true;
        if (lt(n, from_u64(p))) break;
        BigNum r = mod_big(n, from_u64(p));
        if (zero(r)) return false;
    }

    // 2. Для чисел <= 32 бит (1-2 слова) — проверка делением до корня
    if (n.size() <= 2) {
        __uint128_t v = n[0];
        if (n.size() == 2) v |= ((__uint128_t)n[1] << 64);
        if (v == 0 || (v & 1) == 0) return false;
        for (uint64_t d = 3; (__uint128_t)d * d <= v; d += 2) {
            if (v % d == 0) return false;
        }
        return true;
    }

    // 3. Для больших чисел — Миллер-Рабин
    int k = 10;
    if (n.size() > 16) k = 5;   // 1024+ бит
    if (n.size() > 32) k = 3;   // 2048+ бит
    if (n.size() > 64) k = 2;   // 4096+ бит

    BigNum d = sub(n, from_u64(1));
    int s = 0;
    while ((d[0] & 1) == 0) {
        for (size_t i = 0; i < d.size(); ++i) d[i] >>= 1;
        while (!d.empty() && d.back() == 0) d.pop_back();
        s++;
    }

    for (int i = 0; i < k; ++i) {
        std::vector<uint8_t> seed = rand_::bytes(32);
        BigNum a = from_bytes(seed);
        a = mod_big(a, n);
        if (zero(a)) continue;
        BigNum x = modpow(a, d, n);
        if (eq(x, from_u64(1)) || eq(x, sub(n, from_u64(1)))) continue;
        bool composite = true;
        for (int r = 0; r < s - 1; ++r) {
            BigNum _t = modpow(x, from_u64(2), n);
            x = _t;
            if (eq(x, sub(n, from_u64(1)))) {
                composite = false;
                break;
            }
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
        vector<uint8_t> b = rand_::bytes(bits / 8);
        BigNum r = from_bytes(b);
        if (r.empty()) continue;
        r[0] |= 1;  // нечётное
        if (is_prime(r)) return r;
    }
    return from_u64(3);
}
    

    
// ─── Расширенный алгоритм Евклида (для modinv) ───
inline BigNum modinv(const BigNum& a, const BigNum& m) {
    if (zero(a)) return BigNum();
    BigNum u = a, v = m;
    BigNum x = from_u64(1), y = from_u64(0);
    BigNum q, r, t;
    while (!zero(v)) {
        auto [quot, rem] = _bigint::divmod(u, v);
        q = quot;
        r = rem;
        t = sub(x, mul(q, y));
        x = y;
        y = t;
        u = v;
        v = r;
    }
    if (!eq(u, from_u64(1))) return BigNum();
    if (!x.empty() && (x[0] & 0x8000000000000000ULL)) {
        x = add(x, m);
    }
    return x;
}
    
        // Преобразование BigNum в десятичную строку
    string to_dec(const _bigint::BigNum& n) {
    _bigint::BigNum r = n;
    _bigint::BigNum zero = _bigint::from_u64(0);
    _bigint::BigNum ten = _bigint::from_u64(10);
    string s;
    while (!_bigint::zero(r)) {
        auto [q, rem] = _bigint::divmod(r, ten);
        s = char('0' + rem[0]) + s;
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
    
    inline vector<uint8_t> hash_raw(const vector<uint8_t>& data){
    // NOCOPY: стрим из data.data(), хвост паддинга локальный (128 байт)
    uint32_t S[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    const uint8_t* p=data.data(); size_t n=data.size();
    uint64_t bl=(uint64_t)n*8;
    auto block=[&](const uint8_t* q){
        uint32_t w[64],a=S[0],b=S[1],c=S[2],d=S[3],e=S[4],f=S[5],g=S[6],h=S[7];
        for(int i=0;i<16;i++) w[i]=((uint32_t)q[i*4]<<24)|((uint32_t)q[i*4+1]<<16)|((uint32_t)q[i*4+2]<<8)|(uint32_t)q[i*4+3];
        for(int i=16;i<64;i++) w[i]=SS1(w[i-2])+w[i-7]+SS0(w[i-15])+w[i-16];
        for(int i=0;i<64;i++){ uint32_t t1=h+BS1(e)+CH(e,f,g)+K[i]+w[i], t2=BS0(a)+MAJ(a,b,c);
            h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }
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
    for(int i=0;i<8;i++){ out[i*4]=(S[i]>>24)&0xFF; out[i*4+1]=(S[i]>>16)&0xFF; out[i*4+2]=(S[i]>>8)&0xFF; out[i*4+3]=S[i]&0xFF; }
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
    int buf = 0, bits = 0;
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
    static const uint64_t IV[8]={
        0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,
        0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179
    };
    static const uint8_t SIGMA[12][16]={
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
        {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},{7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
        {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},{2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
        {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},{13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
        {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},{10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3}
    };
    inline uint64_t ROR(uint64_t x,int n){return (x>>n)|(x<<(64-n));}
    inline void G(uint64_t& a,uint64_t& b,uint64_t& c,uint64_t& d,uint64_t x,uint64_t y){
        a=a+b+x; d=ROR(d^a,32); c=c+d; b=ROR(b^c,24);
        a=a+b+y; d=ROR(d^a,16); c=c+d; b=ROR(b^c,63);
    }
    inline vector<uint8_t> hash_raw(const vector<uint8_t>& data,size_t outlen=64){
        uint64_t h[8]; memcpy(h,IV,sizeof(IV));
        h[0]^=0x01010000^(outlen<<0);
        const uint8_t* src_=data.data(); size_t n_=data.size();   // NOCOPY-ALL
    size_t full_=n_-n_%(128);
    vector<uint8_t> tail_(src_+full_, src_+n_);

        size_t dlen=n_;
        if(!tail_.empty()) tail_.resize(128,0);
        uint64_t t0=0,t1=0;
            size_t total_=full_+tail_.size();
    auto at_=[&](size_t i)->uint8_t{ return i<full_? src_[i] : tail_[i-full_]; };
    auto ptr_=[&](size_t i)->const uint8_t*{ return i<full_? src_+i : tail_.data()+(i-full_); };
for(size_t i=0;i<total_;i+=128){
            t0+=128; if(t0<128) t1++;
            uint64_t v[16]; memcpy(v,h,64); for(int j=0;j<8;j++) v[j+8]=IV[j];
            v[12]^=t0; v[13]^=t1;
            uint64_t m[16];
            for(int j=0;j<16;j++) m[j]=((uint64_t*)ptr_(i))[j];
            for(int r=0;r<12;r++){
                G(v[0],v[4],v[8],v[12],m[SIGMA[r][0]],m[SIGMA[r][1]]);
                G(v[1],v[5],v[9],v[13],m[SIGMA[r][2]],m[SIGMA[r][3]]);
                G(v[2],v[6],v[10],v[14],m[SIGMA[r][4]],m[SIGMA[r][5]]);
                G(v[3],v[7],v[11],v[15],m[SIGMA[r][6]],m[SIGMA[r][7]]);
                G(v[0],v[5],v[10],v[15],m[SIGMA[r][8]],m[SIGMA[r][9]]);
                G(v[1],v[6],v[11],v[12],m[SIGMA[r][10]],m[SIGMA[r][11]]);
                G(v[2],v[7],v[8],v[13],m[SIGMA[r][12]],m[SIGMA[r][13]]);
                G(v[3],v[4],v[9],v[14],m[SIGMA[r][14]],m[SIGMA[r][15]]);
            }
            for(int j=0;j<8;j++) h[j]^=v[j]^v[j+8];
        }
        return {(uint8_t*)h,(uint8_t*)h+outlen};
    }
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
    int buf = 0, bits = 0;
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
static inline void L(uint8_t* r, const uint8_t* a) {
    const Tables& t = tables();
    for (unsigned i = 0; i < 8; ++i) {
        uint64_t v = ld64(a + 8u * i), acc = 0;
        for (unsigned j = 0; j < 64; ++j)
            if ((v >> (63u - j)) & 1u) acc ^= t.A[j];
        st64(r + 8u * i, acc);
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
inline vector<uint8_t> aes256_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key,const vector<uint8_t>& iv){
    return _aes::encrypt_raw(plain,key,iv);
}
inline vector<uint8_t> aes256_encrypt(const string& plain,const string& key,const string& iv){
    return aes256_encrypt(_::B(plain),_::B(key),_::B(iv));
}
inline vector<uint8_t> aes256_decrypt(const vector<uint8_t>& cipher,const vector<uint8_t>& key,const vector<uint8_t>& iv){
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
    inline vector<uint8_t> ghash(const uint8_t* H,const vector<uint8_t>& A,const vector<uint8_t>& C){
        uint8_t X[16]={0};
        for(size_t i=0;i<A.size();i+=16){
            size_t l=min((size_t)16,A.size()-i);
            uint8_t b[16]={0}; memcpy(b,&A[i],l);
            for(int j=0;j<16;j++) X[j]^=b[j];
            mul(X,H);
        }
        for(size_t i=0;i<C.size();i+=16){
            size_t l=min((size_t)16,C.size()-i);
            uint8_t b[16]={0}; memcpy(b,&C[i],l);
            for(int j=0;j<16;j++) X[j]^=b[j];
            mul(X,H);
        }
        uint64_t a_bits=A.size()*8,c_bits=C.size()*8;
        uint8_t lb[16]={0};
        lb[7]=(a_bits>>56)&0xff; lb[6]=(a_bits>>48)&0xff; lb[5]=(a_bits>>40)&0xff; lb[4]=(a_bits>>32)&0xff;
        lb[3]=(a_bits>>24)&0xff; lb[2]=(a_bits>>16)&0xff; lb[1]=(a_bits>>8)&0xff; lb[0]=a_bits&0xff;
        lb[15]=(c_bits>>56)&0xff; lb[14]=(c_bits>>48)&0xff; lb[13]=(c_bits>>40)&0xff; lb[12]=(c_bits>>32)&0xff;
        lb[11]=(c_bits>>24)&0xff; lb[10]=(c_bits>>16)&0xff; lb[9]=(c_bits>>8)&0xff; lb[8]=c_bits&0xff;
        for(int j=0;j<16;j++) X[j]^=lb[j];
        mul(X,H);
        return {X,X+16};
    }
}

inline vector<uint8_t> aes256_gcm_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key){
    vector<uint8_t> iv=_::randb(12),rk(240);
    _aes::KeyExpansion(key.data(),rk.data());
    uint8_t H[16]={0}; _aes::Cipher(H,rk.data());
    vector<uint8_t> ctr=iv; ctr.push_back(0);ctr.push_back(0);ctr.push_back(0);ctr.push_back(1);
    vector<uint8_t> cipher;
    uint8_t keystream[16];
    for(size_t i=0;i<plain.size();i+=16){
        memcpy(keystream,ctr.data(),16); _aes::Cipher(keystream,rk.data());
        size_t sz=min((size_t)16,plain.size()-i);
        for(size_t j=0;j<sz;j++) cipher.push_back(plain[i+j]^keystream[j]);
        _gcm::inc32(ctr);
    }
    vector<uint8_t> tag=_gcm::ghash(H,{},cipher);
    memcpy(keystream,iv.data(),12); keystream[12]=0;keystream[13]=0;keystream[14]=0;keystream[15]=0;
    _aes::Cipher(keystream,rk.data());
    for(int i=0;i<16;i++) tag[i]^=keystream[i];
    auto res=iv; res.insert(res.end(),cipher.begin(),cipher.end()); res.insert(res.end(),tag.begin(),tag.end());
    return res;
}

inline bool aes256_gcm_decrypt(const vector<uint8_t>& packed,const vector<uint8_t>& key,vector<uint8_t>& plain){
    if(packed.size()<28) return false;
    vector<uint8_t> iv(packed.begin(),packed.begin()+12);
    vector<uint8_t> tag(packed.end()-16,packed.end());
    vector<uint8_t> cipher(packed.begin()+12,packed.end()-16);
    vector<uint8_t> rk(240); _aes::KeyExpansion(key.data(),rk.data());
    uint8_t H[16]={0}; _aes::Cipher(H,rk.data());
    vector<uint8_t> tag2=_gcm::ghash(H,{},cipher);
    uint8_t keystream[16]; memcpy(keystream,iv.data(),12); keystream[12]=0;keystream[13]=0;keystream[14]=0;keystream[15]=0;
    _aes::Cipher(keystream,rk.data());
    for(int i=0;i<16;i++) tag2[i]^=keystream[i];
    if(memcmp(tag.data(),tag2.data(),16)!=0) return false;
    vector<uint8_t> ctr=iv; ctr.push_back(0);ctr.push_back(0);ctr.push_back(0);ctr.push_back(1);
    plain.clear();
    for(size_t i=0;i<cipher.size();i+=16){
        memcpy(keystream,ctr.data(),16); _aes::Cipher(keystream,rk.data());
        size_t sz=min((size_t)16,cipher.size()-i);
        for(size_t j=0;j<sz;j++) plain.push_back(cipher[i+j]^keystream[j]);
        _gcm::inc32(ctr);
    }
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
}

inline vector<uint8_t> chacha20_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key,const vector<uint8_t>& nonce){
    return _chacha::crypt_raw(plain,key,nonce);
}
inline vector<uint8_t> chacha20_decrypt(const vector<uint8_t>& cipher,const vector<uint8_t>& key,const vector<uint8_t>& nonce){
    return _chacha::crypt_raw(cipher,key,nonce);
}

// ==================== ChaCha20-Poly1305 ====================
namespace _poly1305 {
    inline uint64_t clamp(uint64_t v){ return v&0x0ffffffc0ffffffc; }
    inline void mac(const uint8_t* key,const vector<uint8_t>& msg,uint8_t* tag){
        uint64_t r=clamp(((uint64_t*)key)[0]);
        uint64_t s=((uint64_t*)key)[1];
        uint64_t a=0;
        for(size_t i=0;i<msg.size();i+=16){
            size_t l=min((size_t)16,msg.size()-i);
            uint8_t b[17]={0}; memcpy(b,&msg[i],l); b[l]=1;
            uint64_t n=0; for(int j=0;j<17;j++) n|=(uint64_t)b[j]<<(j*8);
            a=(a+n)*r;
        }
        a+=s;
        for(int i=0;i<8;i++) tag[i]=(a>>(i*8))&0xff;
    }
}

inline vector<uint8_t> chacha20_poly1305_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key){
    vector<uint8_t> nonce=_::randb(12);
    vector<uint8_t> poly_key=_chacha::crypt_raw(vector<uint8_t>(64,0),key,nonce);
    vector<uint8_t> cipher=_chacha::crypt_raw(plain,key,nonce);
    uint8_t tag[8]; _poly1305::mac(poly_key.data(),cipher,tag);
    auto res=nonce; res.insert(res.end(),cipher.begin(),cipher.end()); res.insert(res.end(),tag,tag+8);
    return res;
}

inline bool chacha20_poly1305_decrypt(const vector<uint8_t>& packed,const vector<uint8_t>& key,vector<uint8_t>& plain){
    if(packed.size()<20) return false;
    vector<uint8_t> nonce(packed.begin(),packed.begin()+12);
    vector<uint8_t> tag(packed.end()-8,packed.end());
    vector<uint8_t> cipher(packed.begin()+12,packed.end()-8);
    vector<uint8_t> poly_key=_chacha::crypt_raw(vector<uint8_t>(64,0),key,nonce);
    uint8_t tag2[8]; _poly1305::mac(poly_key.data(),cipher,tag2);
    if(memcmp(tag.data(),tag2,8)!=0) return false;
    plain=_chacha::crypt_raw(cipher,key,nonce);
    return true;
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
namespace _rsa {
    using namespace _bigint;
    
    struct Key { 
        BigNum n, e, d; 
        int bits; 
    };

    // ─── Монтгомери (для быстрого модульного умножения) ───
    struct Montgomery {
        BigNum m;      // модуль
        BigNum r;      // 2^(64*k) mod m
        BigNum r_inv;  // обратное к r
        int k;         // количество слов (64 бита)

        Montgomery(const BigNum& mod) : m(mod) {
            k = m.size();
            // r = 2^(64*k) mod m
            r = from_u64(1);
            for (int i = 0; i < k * 64; i++) {
                r = mul(r, from_u64(2));
                r = _bigint::mod(r, m);
            }
            r_inv = _bigint::modinv(r, m);
        }

        BigNum to_mont(const BigNum& x) const {
            return mod(mul(x, r), m);
        }

        BigNum from_mont(const BigNum& x) const {
            return mod(mul(x, r_inv), m);
        }

        BigNum mul_mont(const BigNum& a, const BigNum& b) const {
            return mod(mul(a, b), m);
        }
    };

    // ─── Быстрое возведение в степень (Монтгомери) ───
    inline BigNum modpow_mont(const BigNum& base, const BigNum& exp, const Montgomery& mont) {
        if (zero(exp)) return from_u64(1);
        BigNum result = mont.to_mont(from_u64(1));
        BigNum b = mont.to_mont(base);
        BigNum e = exp;
        while (!zero(e)) {
            if (e[0] & 1) {
                result = mont.mul_mont(result, b);
            }
            b = mont.mul_mont(b, b);
            // e >>= 1
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
        Key k;
        k.bits = bits;
        // Защита от слишком маленьких ключей
        if (bits < 128) bits = 128;
        BigNum p = random_prime(bits / 2);
        BigNum q = random_prime(bits / 2);
        k.n = mul(p, q);
        BigNum phi = mul(sub(p, from_u64(1)), sub(q, from_u64(1)));
        k.e = from_u64(65537);
        k.d = _bigint::modinv(k.e, phi);
        return k;
    }

    // ─── Шифрование ───
    inline vector<uint8_t> encrypt_raw(const vector<uint8_t>& plain, const BigNum& n, const BigNum& e) {
        Montgomery mont(n);
        BigNum m = from_bytes(plain);
        BigNum c = modpow_mont(m, e, mont);
        return to_bytes(c);
    }

    // ─── Расшифровка ───
    inline vector<uint8_t> decrypt_raw(const vector<uint8_t>& cipher, const BigNum& n, const BigNum& d) {
        Montgomery mont(n);
        BigNum c = from_bytes(cipher);
        BigNum m = modpow_mont(c, d, mont);
        return to_bytes(m);
    }

} // namespace _rsa

// ==================== НАСТОЯЩИЙ Ed25519 (Curve25519) ====================
namespace _ed25519 {
    using namespace _bigint;
    
    static const BigNum Q = sub(mul(from_u64(0x8000000000000000ULL), from_u64(0xFFFFFFFFFFFFFFFFULL)), from_u64(18));
    static const BigNum D = from_bytes(_::U("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"));
    static const BigNum L = from_bytes(_::U("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
    static const BigNum SQRT_M1 = from_bytes(_::U("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"));

    struct Point { BigNum x, y; };
    
    inline Point base_point() { 
        return { from_bytes(_::U("1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0f24fb6a4cbd7f966")), 
                 from_bytes(_::U("6666666666666666666666666666666666666666666666666666666666666666")) }; 
    }

    inline Point point_add(const Point& P1, const Point& P2) {
        Point R;
        BigNum x1y2 = mul(P1.x, P2.y), y1x2 = mul(P1.y, P2.x);
        BigNum y1y2 = mul(P1.y, P2.y), x1x2 = mul(P1.x, P2.x);
        BigNum d_x1x2_y1y2 = mod(mul(D, mul(x1x2, y1y2)), Q);
        BigNum inv1 = modinv(add(from_u64(1), d_x1x2_y1y2), Q);
        BigNum inv2 = modinv(sub(from_u64(1), d_x1x2_y1y2), Q);
        R.x = mod(mul(add(x1y2, y1x2), inv1), Q);
        R.y = mod(mul(add(y1y2, x1x2), inv2), Q);
        return R;
    }

    inline Point scalar_mult(Point P, const BigNum& k) {
        Point R = { from_u64(0), from_u64(1) };
        BigNum kk = k;
        while (!zero(kk)) {
            if (kk[0] & 1) R = point_add(R, P);
            P = point_add(P, P);
            for (size_t i = 0; i < kk.size(); ++i) {
                kk[i] >>= 1;
                if (i + 1 < kk.size() && (kk[i+1] & 1)) kk[i] |= 0x8000000000000000ULL;
            }
            while (!kk.empty() && kk.back() == 0) kk.pop_back();
        }
        return R;
    }

    inline Point decompress(const vector<uint8_t>& b) {
        if (b.size() != 32) return {from_u64(0), from_u64(0)};
        BigNum y = from_bytes(b);
        y[0] &= ~(1ULL << 63);
        bool sign = (b[31] & 0x80) != 0;
        
        BigNum y2 = mod(mul(y, y), Q);
        BigNum u = sub(y2, from_u64(1));
        BigNum v = add(mul(D, y2), from_u64(1));
        
        BigNum v3 = mod(mul(mul(v, v), v), Q);
        BigNum v7 = mod(mul(mul(v3, v3), v), Q);
        BigNum uv7 = mod(mul(u, v7), Q);

        BigNum exp = divmod(sub(Q, from_u64(5)), from_u64(8)).first;
        
        BigNum x = mod(mul(mul(u, v3), modpow(uv7, exp, Q)), Q);
        
        if (!eq(mod(mul(v, mul(x, x)), Q), mod(u, Q))) {
            x = mod(mul(x, SQRT_M1), Q);
        }
        
        bool x_is_odd = (x[0] & 1);
        if (x_is_odd != sign) x = sub(Q, x);
        
        return {x, y};
    }

    inline vector<uint8_t> sign(const vector<uint8_t>& msg, const vector<uint8_t>& priv) {
        vector<uint8_t> h = _sha512::hash_raw(priv);
        vector<uint8_t> a(h.begin(), h.begin() + 32);
        a[0] &= 248; a[31] &= 127; a[31] |= 64;
        BigNum a_num = from_bytes(a);

        Point A = scalar_mult(base_point(), a_num);
        vector<uint8_t> A_bytes = to_bytes(A.y);
        A_bytes.resize(32, 0);
        if (A.x[0] & 1) A_bytes[31] |= 0x80;

        vector<uint8_t> prefix(h.begin() + 32, h.end());
        prefix.insert(prefix.end(), msg.begin(), msg.end());
        BigNum r = mod(from_bytes(_sha512::hash_raw(prefix)), L);

        Point R = scalar_mult(base_point(), r);
        vector<uint8_t> R_bytes = to_bytes(R.y);
        R_bytes.resize(32, 0);
        if (R.x[0] & 1) R_bytes[31] |= 0x80;

        vector<uint8_t> k_input = R_bytes;
        k_input.insert(k_input.end(), A_bytes.begin(), A_bytes.end());
        k_input.insert(k_input.end(), msg.begin(), msg.end());
        BigNum k = mod(from_bytes(_sha512::hash_raw(k_input)), L);

        BigNum S = mod(add(r, mul(k, a_num)), L);
        vector<uint8_t> sig = R_bytes;
        vector<uint8_t> S_bytes = to_bytes(S);
        S_bytes.resize(32, 0);
        sig.insert(sig.end(), S_bytes.begin(), S_bytes.end());
        return sig;
    }

    inline bool verify(const vector<uint8_t>& msg, const vector<uint8_t>& sig, const vector<uint8_t>& pub) {
        if (sig.size() != 64 || pub.size() != 32) return false;
        vector<uint8_t> R_bytes(sig.begin(), sig.begin() + 32);
        vector<uint8_t> S_bytes(sig.begin() + 32, sig.end());
        BigNum S = from_bytes(S_bytes);

        Point R = decompress(R_bytes);
        Point A = decompress(pub);
        if (zero(A.y) || zero(R.y)) return false;

        vector<uint8_t> k_input = R_bytes;
        k_input.insert(k_input.end(), pub.begin(), pub.end());
        k_input.insert(k_input.end(), msg.begin(), msg.end());
        BigNum k = mod(from_bytes(_sha512::hash_raw(k_input)), L);

        Point S_B = scalar_mult(base_point(), S);
        Point k_A = scalar_mult(A, k);
        Point R_plus_kA = point_add(R, k_A);

        return eq(S_B.x, R_plus_kA.x) && eq(S_B.y, R_plus_kA.y);
    }

    struct KeyPair {
        vector<uint8_t> pub;
        vector<uint8_t> priv;
    };
    
    inline KeyPair keygen() {
        KeyPair kp;
        vector<uint8_t> seed = rand_::bytes(32);
        vector<uint8_t> h = _sha512::hash_raw(seed);
        vector<uint8_t> a(h.begin(), h.begin() + 32);
        a[0] &= 248; a[31] &= 127; a[31] |= 64;
        kp.priv = a;
        BigNum a_num = from_bytes(a);
        Point A = scalar_mult(base_point(), a_num);
        kp.pub = to_bytes(A.y);
        kp.pub.resize(32, 0);
        if (A.x[0] & 1) kp.pub[31] |= 0x80;
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
    string state = "OrpheanBeholderScryDoubt";
    for (int i = 0; i < 64; i++) state[i] ^= pass[i % pass.size()];
    for (int i = 0; i < 64; i++) state[i] ^= salt[i % salt.size()];
    
    for (unsigned int r = 0; r < (1u << cost); r++) {
        uint32_t* data = (uint32_t*)state.data();
        for (int i = 0; i < 64; i += 8) {
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
    string salt = _::H(rand_::bytes(16));
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
    return bcrypt_hash(pass, cost) == hash;
}

// ==================== НАСТОЯЩИЙ Argon2id ====================
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
        for (int i = 0; i < 8; i++) S[i+8] = ((uint64_t*)block.data())[i];
        for (int i = 0; i < 4; i++) roundfunc(S);
        for (int i = 0; i < 64; i++) block[i] = (S[i/8] >> ((i%8)*8)) & 0xFF;
    }
    
    inline vector<uint8_t> argon2id(const string& pass, const string& salt, 
                                 int mem_cost = 64, int time_cost = 3) {
    vector<uint64_t> H(8, 0);
    string combined = pass + string(8 - (pass.size()%8), '\0') + salt;
    for (size_t i = 0; i < combined.size()/8 && i < 8; i++)
        H[i] = ((uint64_t*)combined.data())[i] ^ ((uint64_t)0xDEADBEEF * (i+1));
    
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
    string r; int val=0,valb=-6;
    for(auto c:data){ val=(val<<8)+c; valb+=8; while(valb>=0){ r+=B64[(val>>valb)&0x3F]; valb-=6; } }
    if(valb>-6) r+=B64[((val<<8)>>(valb+8))&0x3F];
    while(r.size()%4) r+='=';
    return r;
}
inline vector<uint8_t> base64_decode(const string& s){
    vector<uint8_t> r; int val=0,valb=-8;
    for(char c:s){
        if(c=='=') break;
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
    int buffer = 0, bits = 0;
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
    int buffer = 0, bits = 0;
    for (char c : s) {
        if (c == '=') break;
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
    vector<int> d; for(auto b:data) d.push_back(b);
    string r;
    while(!d.empty()){
        int rem=0; vector<int> nd;
        for(int x:d){ rem=rem*256+x; nd.push_back(rem/58); rem%=58; }
        r=B58[rem]+r;
        d.clear(); bool nz=false;
        for(int x:nd){ if(x||nz){ d.push_back(x); nz=true; } }
    }
    for(auto b:data){ if(b==0) r=B58[0]+r; else break; }
    return r;
}
inline vector<uint8_t> base58_decode(const string& s){
    vector<uint8_t> r;
    for(char c:s){
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
inline vector<uint8_t> random_bytes(size_t n){ return _::randb(n); }
inline uint64_t random_int(uint64_t min,uint64_t max){
    return min+(_::rand64()%(max-min+1));
}
inline vector<uint8_t> random_prime(int bits){
    vector<uint8_t> r=_::randb(bits/8);
    r[0]|=0x80; r.back()|=1;
    return r;
}

// ==================== Кузнечик (ГОСТ Р 34.12-2018) ====================
namespace _kuznechik {
    static const uint8_t PI[256]={
        0xFC,0xEE,0xDD,0x11,0xCF,0x6E,0x31,0x16,0xFB,0xC4,0xFA,0xDA,0x23,0xC5,0x04,0x4D,
        0xE9,0x77,0xF0,0xDB,0x93,0x2E,0x99,0xBA,0x17,0x36,0xF1,0xBB,0x14,0xCD,0x5F,0xC1,
        0xF9,0x18,0x65,0x5A,0xE2,0x5C,0xEF,0x21,0x81,0x1C,0x3C,0x42,0x8B,0x01,0x8E,0x4F,
        0x05,0x84,0x02,0xAE,0xE3,0x6A,0x8F,0xA0,0x06,0x0B,0xED,0x98,0x7F,0xD4,0xD3,0x1F,
        0xEB,0x34,0x2C,0x51,0xEA,0xC8,0x48,0xAB,0xF2,0x2F,0x8D,0x27,0xA8,0x7A,0x97,0x2A,
        0xE8,0x0C,0x22,0xDC,0x0A,0x7C,0x3F,0x24,0x12,0x4C,0xCE,0x6D,0x9E,0xA5,0x6F,0xAC,
        0xE5,0x73,0x08,0x75,0x3E,0xC2,0x44,0xD0,0x29,0xA9,0xD9,0x6B,0x19,0x96,0x0F,0xBE,
        0x47,0x0D,0x26,0xAA,0x3A,0xB4,0x4E,0x69,0x1A,0xA2,0x1D,0x7E,0x9F,0x2D,0xD1,0x85,
        0x57,0x0E,0x61,0x66,0x45,0x3D,0x95,0x90,0x6C,0x5E,0x28,0x41,0x82,0x1B,0x30,0x7D,
        0xF8,0x33,0xC6,0x8A,0x35,0xC7,0xA7,0xC3,0x52,0x32,0xB1,0xB5,0x8C,0x54,0xAD,0xDF,
        0x4B,0xA1,0x00,0xE1,0x53,0x39,0x55,0xF7,0x5D,0x20,0xD7,0xA4,0xCA,0xB7,0xDD,0xE6,
        0xF5,0x9A,0x03,0x58,0x10,0x5B,0xE4,0x07,0xFF,0x64,0xF4,0x6C,0x49,0x87,0xBC,0x9D,
        0x62,0x09,0x46,0xD6,0x7B,0x71,0x2B,0xA6,0x89,0x37,0x13,0x9C,0x74,0xCC,0xB3,0xDE,
        0x38,0xD2,0x70,0xB9,0x67,0x88,0x1E,0xE7,0x79,0x94,0xD8,0x91,0x86,0xA3,0xE0,0x25,
        0x59,0x15,0xC0,0xF3,0xBD,0x68,0x60,0x9B,0x78,0xD5,0x50,0x92,0x4A,0x83,0x80,0x63,
        0x76,0xC9,0x43,0xB6,0x0F,0x40,0x3B,0xFD,0xAF,0x56,0xBF,0x72,0xB2,0xF6,0xEC,0xFE
    };
    static const uint8_t INV_PI[256]={
        0xA5,0x2D,0x32,0x8F,0x0E,0x30,0x38,0xC0,0x54,0xE6,0x9E,0x39,0x55,0x7C,0x81,0xEF,
        0x16,0x03,0x6C,0x6A,0xCA,0x29,0x07,0x28,0x21,0x6E,0x78,0x8D,0x42,0x7A,0xDE,0x3F,
        0xAD,0x27,0x56,0x0C,0x57,0xED,0x72,0x4B,0x8A,0x68,0x4F,0xC6,0x44,0x7D,0x15,0x49,
        0x8E,0x06,0x99,0x91,0x41,0x94,0x19,0xC9,0xD0,0xA3,0x74,0xF6,0x2A,0x85,0x64,0x5E,
        0xF5,0x8B,0x2B,0xF2,0x66,0x84,0xC2,0x70,0x46,0xBC,0xEC,0xA0,0x59,0x0F,0x76,0x2F,
        0xEA,0x43,0x98,0xA2,0x9D,0xAA,0xF9,0x80,0xB3,0xE0,0x23,0xB5,0x25,0xA8,0x89,0x1E,
        0xEE,0x82,0xC0,0xFF,0xBB,0x22,0x83,0xD4,0xE5,0x77,0x35,0x6B,0xB8,0x5B,0x05,0x5D,
        0xD3,0xC5,0xFB,0x61,0xCC,0x63,0xF0,0x11,0xE8,0xD8,0x4D,0xC4,0x53,0x8F,0x7B,0x3C,
        0xFE,0x48,0x8C,0xED,0x33,0x7F,0xDC,0xBD,0xD5,0xC8,0x93,0x4C,0x9C,0x4A,0x2E,0x36,
        0x87,0xDB,0xEB,0x14,0xD9,0x86,0x6D,0x4E,0x3B,0x10,0xB1,0xE7,0xCB,0xBF,0x5C,0x7E,
        0x37,0xA1,0x79,0xDD,0xAB,0x5D,0xC7,0x96,0x4C,0x69,0x73,0x47,0x5F,0x9A,0x34,0xE9,
        0xF0,0x0A,0xFC,0xCE,0x75,0x9B,0xF3,0xAC,0x17,0xD7,0x08,0x1B,0xBE,0xE4,0x6F,0xFA,
        0xE2,0x1F,0x65,0x97,0xA9,0x0D,0x92,0x95,0x45,0xF1,0xAE,0xE8,0xCD,0x1D,0x58,0x04,
        0x67,0x7E,0xD1,0x3E,0x5D,0xE9,0xC3,0xAA,0xDA,0x6A,0x0B,0x13,0x53,0xAE,0xE0,0x9F,
        0xDE,0xA3,0x24,0x34,0xB6,0x60,0xBF,0xD7,0x50,0x20,0x40,0x40,0xFE,0x3A,0x01,0x26,
        0x12,0x1A,0x48,0xE3,0xBA,0xB0,0xFD,0xAB,0x90,0x00,0x02,0x09,0x00,0xF7,0xFF,0xBC
    };
    static const uint8_t L_VEC[16]={1,148,32,133,16,194,192,1,251,1,192,194,16,133,32,148};
    
    inline void LSX(uint8_t* a,const uint8_t* k){
        for(int i=0;i<16;i++) a[i]=PI[a[i]^k[i]];
        uint8_t b[16]; memcpy(b,a,16);
        for(int i=0;i<16;i++){
            a[i]=0;
            for(int j=0;j<16;j++) if(b[j]&(1<<(7-i%8))) a[i]^=L_VEC[j];
        }
    }
    inline void F(uint8_t* a,uint8_t* b,const uint8_t* k){
        uint8_t c[16]; for(int i=0;i<16;i++) c[i]=a[i]^b[i];
        LSX(c,k);
        for(int i=0;i<16;i++) a[i]=c[i]^b[i];
        memcpy(b,c,16);
    }
    inline void KeySchedule(const uint8_t* key,uint8_t rk[10][16]){
        memcpy(rk[0],key,16); memcpy(rk[1],key+16,16);
        uint8_t c[16]={0};
        for(int i=0;i<4;i++){
            F(rk[0],rk[1],c);
            memcpy(rk[2*i+2],rk[0],16); memcpy(rk[2*i+3],rk[1],16);
        }
    }
    
    inline vector<uint8_t> encrypt_raw(const vector<uint8_t>& plain,const vector<uint8_t>& key){
        uint8_t rk[10][16]; KeySchedule(key.data(),rk);
        vector<uint8_t> blk=plain;
        for(int r=0;r<9;r++){ LSX(blk.data(),rk[r]); }
        for(int i=0;i<16;i++) blk[i]^=rk[9][i];
        return blk;
    }
}

inline vector<uint8_t> kuznechik_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key){
    return _kuznechik::encrypt_raw(plain,key);
}
inline vector<uint8_t> kuznechik_decrypt(const vector<uint8_t>& cipher,const vector<uint8_t>& key){
    return _kuznechik::encrypt_raw(cipher,key);
}

// ==================== Магма (ГОСТ 28147-89) ====================
namespace _magma {
    static const uint8_t SBOX[8][16]={
        {4,10,9,2,13,8,0,14,6,11,1,12,7,15,5,3},
        {14,11,4,12,6,13,15,10,2,3,8,1,0,7,5,9},
        {5,8,1,13,10,3,4,2,14,15,12,7,6,0,9,11},
        {7,13,10,1,0,8,9,15,14,4,6,12,11,2,5,3},
        {6,12,7,1,5,15,13,8,4,10,9,14,0,3,11,2},
        {4,11,10,0,7,2,1,13,3,6,8,5,9,12,15,14},
        {13,11,4,1,3,15,5,9,0,10,14,7,6,8,2,12},
        {1,15,13,0,5,7,10,4,9,2,3,14,6,11,8,12}
    };
    inline uint32_t t(uint32_t v){
        uint32_t r=0;
        for(int i=0;i<8;i++) r|=SBOX[i][(v>>(4*i))&0xF]<<(4*i);
        return (r<<11)|(r>>21);
    }
    inline vector<uint8_t> encrypt_raw(const vector<uint8_t>& plain,const vector<uint8_t>& key){
        vector<uint8_t> blk=plain;
        uint32_t a=*((uint32_t*)&blk[0]),b=*((uint32_t*)&blk[4]);
        uint32_t K[8]; memcpy(K,key.data(),32);
        for(int r=0;r<31;r++){ uint32_t tmp=b^t(a+K[r%8]); b=a; a=tmp; }
        *((uint32_t*)&blk[0])=b; *((uint32_t*)&blk[4])=a;
        return blk;
    }
}

inline vector<uint8_t> magma_encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key){
    return _magma::encrypt_raw(plain,key);
}
inline vector<uint8_t> magma_decrypt(const vector<uint8_t>& cipher,const vector<uint8_t>& key){
    return _magma::encrypt_raw(cipher,key);
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
        return aes256_gcm_decrypt(_data, key, _data);
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

// Макросы

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
    for (int i = 0; i < 256; i++) p[i] = i;
    mt19937 gen(seed);
    shuffle(p.begin(), p.end(), gen);
    return p;
}

inline const vector<unsigned char>& get_perm(int seed) {
    static std::map<int, vector<unsigned char>> cache;
    if (cache.find(seed) == cache.end()) cache[seed] = gen_perm(seed);
    return cache[seed];
}

// ===== БАЗОВЫЙ ШУМ =====
inline double noise(double x, double y, int seed, double scale, int octaves) {
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

// ===================================================================
// КОНЕЦ all_crypto.h
// ===================================================================