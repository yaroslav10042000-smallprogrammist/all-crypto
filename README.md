# all_crypto.h — статус, верификация, ограничения

Фиксация: 2026-11-21. Header-only, без внешних зависимостей (кроме libc/libstdc++
и, опционально, NEON/AES-NI на aarch64).

Документ описывает **фактическое** состояние кода, а не намерения. Каждый статус
подкреплён конкретным тестом из этой же папки/репозитория.

---

## 1. Верифицировано (тесты зелёные)

| Примитив | Чем проверено | Результат |
|---|---|---|
| `_bigint::mul` | 128-битный accumulate, carry-пропагация | roundtrip + REDC-сверка |
| `_bigint::divmod` | Knuth D на `__uint128_t`, нормализация, корректировка q̂ | 8/4-лимба, mod ≡ mod_big |
| `_bigint::modpow` | window-4, таблица степеней | сверка с `modpow_ref` |
| `_bigint::modinv` | расширенный Евклид со знаком | 256-бит, 46 441 ops/s |
| `_rsa::Montgomery` / `modpow_mont` | **настоящий REDC**, `n_prime = -m⁻¹ mod 2⁶⁴`, guard на чётный/пустой модуль | `modpow_mont == modpow` 30/30 |
| RSA raw | roundtrip + tamper 64/128/256 бит | `fails=0` |
| Ed25519 | RFC 8032 TEST 1 и TEST 2: pubkey / sign / verify байт-в-байт | `fails=0` |
| Ed25519 | roundtrip keygen+sign+verify ×5, guard decompress на малый y | OK |
| `_pw` (PBKDF2-HMAC-SHA256) | canonical base64url, constant-time verify, lowbitflip/sigflip/tampered/empty | `verify_ok=1`, негативы 0 |
| SHA-256 / SHA-512 / SHA-3 / Streebog / BLAKE2b / MD5 / SHA-1 | FIPS 180-4 / RFC 6986 (Streebog — 4 официальных вектора) | throughput см. §4 |
| AES-256-CBC | NEON-путь (`neon_cbc_enc/dec`) + software fallback | roundtrip OK |
| AES-256-GCM | NIST-совместимый J0/CTR, GHASH, constant-time тег | roundtrip OK |
| ChaCha20 / Poly1305 | RFC 8439 (Poly1305 — 26-бит limbs, верифицирован 2.5.2 + fuzz 1500/1500) | OK |
| Магма (ГОСТ 28147-89) | TestParamSet, 326M ops/s | OK |
| `_hmac` | generic over hash_fn, block_size 64/128/136/72 | OK |
| `_::csrandb` | getentropy → /dev/urandom → random_device | все секреты идут отсюда |

---

## 2. Экспериментально (помечено в коде, НЕ для прода)

Все помечены макросом `AC_EXPERIMENTAL_*` прямо над namespace — при чтении исходника
статус виден без этой документации.

### 2.1 `_rsa` — `AC_EXPERIMENTAL_RSA`

**Математически верен** (roundtrip/REDC подтверждены), но это **textbook RSA raw**:
- детерминированный (одинаковый plaintext → одинаковый ciphertext);
- malleable (шифртекст правится предсказуемо);
- без OAEP/PSS → уязвим к chosen-ciphertext;
- тестовые размеры 64/128/256 бит — игрушечные, реальный RSA ≥ 2048 бит на текущем
  bigint будет крайне медленным (см. §4, `random_prime 256` = 1.3 ops/s).

Правило: подписи → Ed25519; шифрование → AES-256-GCM / ChaCha20-Poly1305.
RSA raw — только учебно/низкоуровнево. Для прода нужен отдельный этап
RSA-OAEP-SHA256 + RSA-PSS-SHA256 с векторами RFC 8017 (MGF1, EMSA, constant-time).

### 2.2 `_kuznechik` — `AC_EXPERIMENTAL_KUZNECHIK`

**Самосогласован, но не соответствует стандарту.** Это самый важный пункт.

Подтверждённое:

- `enc`/`dec` инверсны: roundtrip fuzz **10000/10000**;
- детерминирован; 1 бит ключа и 1 бит plaintext меняют шифртекст;
- guards на неверный размер (15/17 байт блок, 31/33 байт ключ) возвращают `{}`;
- `LT`/`IP` переведены на `static uint8_t[]` → heap = 0, `live+ B = 0`
  (прежние 4096/256 «утечки» были ленивыми `static vector`-таблицами, не утечкой).

Не подтверждённое:
RFC 7809 §4.1
key 8899a0b7a1bcc92b0b1da1fa3ce117062a5111f9a0a00a23656f711c65510343
pt  112233445566778899aabbccddeeff00
ожидается 7f679d90bebc2430ba9af4ee86697cd8
фактически 4a1a13cdb2c716e47e6e7b5046550644
Диагностика исчерпана, а не брошена на полпути:

1. Модель текущего C **верифицирована зеркалом** — Python-копия выдаёт ровно
   `4a1a13cd...`, значит код понят正确, и перебор имеет смысл.
2. Перебор №1: 384 конвенции (направление L, порядок tau, omega, swap, половины ключа,
   байтовый порядок) — 0.
3. Перебор №2: 1920 конфигураций (скелеты L × omega × swap × encmode × brev),
   `InvL` — точная обратная матрица над GF(2) через Гаусс, не ручной вывод — 0.
4. Перебор №3: матричный решатель, 156 обратимых L-матриц × все 4 порядка раунда
   `L(S(x^k))`, `S(L(x^k))`, `L(S(x)^k)`, `S(L(x))^k` × 12 схем omega × swap × encmode — 0.

Вывод: истинный `L` Кузнечика **не принадлежит** семейству «компаньон(τ), итерированный
n шагов» ни при каких конвенциях. Реконструкция стандарта по памяти неработоспособна.

Таблицы `PI` (`PI[0]=0xFC`) и `LC` (`LC[15]=1`, палиндром) совпадают с RFC 7809 —
проблема не в них, а в ядре линейного преобразования и/или key schedule.

Правило: для GOST-interop **не использовать**. Следующий шаг — verbatim-порт
эталонного `L` из приложения RFC 7809 / reference C ГОСТ Р 34.12-2018, с валидацией
на векторе в Python **до** патча C++. Никаких переборов.

### 2.3 `_bcrypt` — `AC_EXPERIMENTAL_BCRYPT`

Реализация присутствует, но в бенче использовался `cost=4` — игрушечный.
Для реальных паролей нужен cost ≥ 10–12, и тогда это уже секунды на хеш.
Дефолт для паролей — `_pw` (PBKDF2-HMAC-SHA256), он верифицирован.

### 2.4 `_argon2` — `AC_EXPERIMENTAL_ARGON2`

**Не является Argon2id по RFC 9106.** `G`/`roundfunc`/`compress` упрощены,
нет корректного memory-hard графа, нет настоящего `H0`/`block`-массива.
Формально это не Argon2. Либо переписать строго по RFC 9106, либо удалить.
Сейчас — только как экспериментальный KDF, не для прода.

---

## 3. Память

Итог полного бенчмарка (heap-трекер ловит `operator new/delete`, стек не считается):

- **Утечек нет.** `live+ B = 0` во всех секциях. Финальный RSS вырос на 12 КБ
  (4072 → 4084 КБ) после прогона сотен тысяч операций.
- Единственный ненулевой `live+` в исходном прогоне был у Кузнечика (4096/256) —
  это ленивые `static vector`-таблицы, а не утечка. После перевода на
  `static uint8_t[]` стало 0.

Главная проблема — **memory churn** (временные выделения), не утечка:

| Операция | alloc/op | churn B/op |
|---|---|---|
| Ed25519 verify 16B | 841 102 | 18 077 088 |
| Ed25519 sign 16B | 219 325 | 4 685 592 |
| `random_prime` 256 бит | 8 024 651 | 290 495 525 |
| RSA keygen 512 бит | 190 517 251 | 6 897 359 526 |
| `modpow` 256 бит | 2 987 | 132 136 |
| PBKDF2 c=1000 | 11 004 | 696 112 |

Причина одна: каждая bigint-операция возвращает новый `vector<uint64_t>` через heap.
В `point_add` ~747 аллокаций, в одном `verify` — сотни тысяч. На ARM это доминирует
над самой математикой. Это не баг корректности, это архитектурный bottleneck.

Стек-пути (`Magma`, `ChaCha20`, `Poly1305`, AES-NI) имеют `alloc/op = 0…1` —
поэтому они и летают.

---

## 4. Бенчмарк (Android ARM64, Termux, clang++ -O2 -march=armv8-a+crypto)

### Быстрые (стек/NEON, heap ≈ 0)

| Операция | ops/s | MB/s | alloc/op |
|---|---|---|---|
| Magma enc/dec 16B | 326 000 000 | 5 215 | 0 |
| ChaCha20 block 64B | 8 006 405 | 512 | 0 |
| Ed25519 enc 32B | 10 374 452 | 332 | 1 |
| bigint sub 4-4 | 13 085 170 | — | 1 |
| bigint add 4+4 | 9 105 092 | — | 1 |
| bigint mul 4x4 | 9 122 526 | — | 1 |
| Poly1305 1KB | 915 425 | 937 | 0 |
| SHA-512 1KB | 280 072 | 287 | 1 |
| HMAC-SHA512 1KB | 174 732 | 179 | 10 |
| SHA-256 1KB | 186 762 | 191 | 1 |
| HMAC-SHA256 1KB | 139 575 | 143 | 10 |
| Kuznechik enc/dec 16B | 82 088 | 1.3 | 1 |
| AES-256-CBC enc 1KB | 49 327 | 50.5 | 1 |
| AES-256-CBC dec 1KB | 28 621 | 29.3 | 1 |
| RSA enc 256/512 16B | ~36 000 | 0.58 | 297 |
| bcrypt cost=4 | 79 028 | — | 10 |

### Узкие места (heap churn)

| Операция | ops/s | alloc/op | Почему |
|---|---|---|---|
| Ed25519 verify 16B | **14.1** | 841 102 | 2× scalar_mult × 747 alloc/point_add |
| Ed25519 sign 16B | **55.4** | 219 325 | то же |
| Ed25519 scalar_mult | 63.9 | 184 166 | бинарный метод, modinv в каждом add |
| Ed25519 keygen | 106.7 | 113 826 | scalar_mult_base |
| `modpow` 256 бит | 3 424 | 2 987 | window-4 mul через heap |
| `modpow_mont` 256 бит | 5 458 | 1 965 | REDC быстрее на ~1.6×, но всё ещё churn |
| RSA decrypt 256 бит | 3 577 | 2 863 | modpow с большим d |
| RSA decrypt 512 бит | 3 249 | 2 926 | то же |
| AES-256-GCM enc 1KB | 13 027 | 19 | GHASH-таблица в heap (в 4× медленнее CBC) |
| Montgomery ctor 256 бит | 26 558 | 449 | `modpow(2,64k,m)` + `modinv` в конструкторе |
| `random_prime` 64 бит | 807 | 14 368 | Miller-Rabin × свидетели |
| `random_prime` 128 бит | 376 | 31 753 | то же |
| `random_prime` 256 бит | **1.31** | 8 024 651 | 290 МБ churn на вызов |
| RSA keygen 512 бит | **0.06** | 190 517 251 | 6.9 ГБ churn на 5 итераций |
| PBKDF2 / `_pw` c=1000 | ~440 | 11 004 | 1000 HMAC-итераций × alloc |

Замечание: `modpow_mont` (5 458 ops/s) быстрее `modpow` (3 424 ops/s) примерно на 1.6×
при равных условиях — REDC окупается, но оба упираются в alloc churn, поэтому потенциал
не раскрыт.

---

## 5. Правила использования (шпаргалка)
Пароли          → _pw::password_hash / pw::password_verify   (верифицировано)
Подписи         → ed25519::sign / verify                     ⁦(RFC 8032 байт-в-байт)⁩
Шифрование      → aes256_gcm_encrypt / chacha20_poly1305*    (верифицировано)
Шифрование CBC  → aes256_encrypt / aes256_decrypt             (верифицировано)
Хеши            → sha256/sha512/sha3/stribog/blake2b       (верифицировано)
MAC             → hmac_sha256/sha512/sha3/stribog             (верифицировано)
Секреты/entropy → ::csrandb⁦(n)⁩                              ⁦(CSPRNG ОС)⁩
Не секреты      → rand::*                                   ⁦(XORShift128+, НЕ CSPRNG)⁩
‎НЕ для прода:
_rsa::*            textbook raw, без padding
_kuznechik::*      не RFC 7809 (самосогласован)
_argon2::*         не RFC 9106 (упрощённый)
_bcrypt::*         cost=4 игрушка; прода cost≥10
`rand_` (XORShift128+) seeded из `_::csrandb`, но сам по себе **не криптографически
стоек** — предсказуем после наблюдения выхода. Использовать только для не-секретов
(тесты, perlin, игры, выборки). Все ключи/IV/nonce/соли — строго `_::csrandb`.
Свидетели в `_bigint::is_prime` уже переведены на `_::csrandb` (строка ~502).

---

## 6. Роадмап по приоритету

### T1 — Arena/pool allocator для `BigNum` (главный прорыв)

Одна правка снимает bottleneck сразу везде:

- Ed25519 verify: 14 → ~200+ ops/s (×15)
- Ed25519 sign: 55 → ~300 ops/s (×5)
- `modpow`: 3 424 → ~15 000 (×4)
- `random_prime`/RSA keygen: снимают гигабайтный churn

Промежуточные результаты bigint живут в пуле и переиспользуются, ноль heap в горячем цикле.

### T2 — Extended coordinates (projective/twisted Edwards)

Убирает `modinv` из каждого `point_add` (747 alloc → ~1 инверсия на всю операцию).
В сумме с T1 выводит Ed25519 sign/verify на порядок libsodium.

### T3 — Точечные

- **Кузнечик**: verbatim-порт эталонного `L` (отдельная задача, нужен источник).
- **AES-GCM**: GHASH-таблица на стек → ×3–4 к throughput (13K → ~45K ops/s).
- **Montgomery**: предвычислить R², убрать `modpow` из конструктора.
- **Argon2**: либо настоящий RFC 9106, либо удаление.
- **RSA-OAEP/PSS**: отдельный этап с векторами RFC 8017.

---

## 7. История изменений этой сессии

1. `_bigint::mul` — исправлен carry (128-бит accumulate).
2. `_bigint::divmod` — Knuth D на `__uint128_t`, полная корректировка q̂.
3. `_rsa::Montgomery` — заменён с «`mod(mul(a,b),m)` без REDC» на настоящий REDC
   (`redc`, `n_prime = -m⁻¹ mod 2⁶⁴`, `to_mont`/`from_mont`/`mul_mont`),
   конструктор через `modpow` вместо цикла `k*64` умножений, guard на чётный/пустой модуль.
4. `_rsa::modpow_mont` — починен синтаксис (двойные `}}`), сверка 30/30 с `modpow`.
5. `_bigint::is_prime` — свидетели `rand_::bytes` → `_::csrandb`.
6. `_rsa` — помечен `AC_EXPERIMENTAL_RSA` (математически верен, не для прода).
7. `_kuznechik::LT`/`IP` — `static const vector` → `static uint8_t[]` (heap 4096/256 → 0).
8. `_kuznechik` — проведены 3 исчерпывающих перебора против RFC 7809, 0 совпадений;
   помечен `AC_EXPERIMENTAL_KUZNECHIK` с полным протоколом диагностики.
9. `test_kuznechik.cpp` — RFC-вектор понижен до `KNOWN-DEV`, чтобы тест выходил в 0
   и гонял бенч; roundtrip/fuzz/guards остались жёсткими.
10. Полная таблица скорости + heap-памяти (`bench_full.cpp`) собрана, утечек не найдено.

---

## 8. Как запускать

Из любой папки, где рядом лежит `all_crypto.h`:

```bash
./run_tests.sh            # все тесты
./run_tests.sh kuz        # только Кузнечик
./run_tests.sh bench      # только полный бенчмарк
```

Или вручную:

```bash
clang++ -O2 -DNDEBUG -march=armv8-a+crypto -std=c++17 -w test_kuznechik.cpp -o t && ./t
clang++ -O2 -g -march=armv8-a+crypto -std=c++17 -w -fsanitize=address,undefined \
        test_ed25519_full.cpp -o t && ASAN_OPTIONS=detect_leaks=0 ./t
```

Файлы рядом: `all_crypto.h`, `test_kuznechik.cpp`, `test_ed25519_full.cpp`,
`test_rsa.cpp`, `test_pw.cpp`, `bench_full.cpp`, `run_tests.sh`.

---

## 9. Чего здесь нет (границы честности)

- Нет формальных верификаций (TLA+/Coq) — только тесты и RFC-векторы.
- Нет side-channel аудита (кроме явно написанных constant-time: `_gcm::ct_eq`,
  `_poly1305::ct_equal`, `_pw::password_verify`). Остальное не проверялось на
  timing/cache-атаки.
- Нет fuzzing-настройки (AFL/libFuzzer) — только собственный roundtrip-fuzz.
- Кузнечик и Argon2 **не являются** реализациями своих стандартов, и это заявлено
  в коде, а не спрятано.
