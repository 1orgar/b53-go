<p align="center">
  <img src="assets/logo.svg" alt="b53-go logo" width="520">
</p>

# b53-go

[English](README.md) | **🇷🇺 Русская версия**

[![Go Reference](https://pkg.go.dev/badge/github.com/1orgar/b53-go.svg)](https://pkg.go.dev/github.com/1orgar/b53-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/1orgar/b53-go/actions/workflows/ci.yml/badge.svg)](https://github.com/1orgar/b53-go/actions/workflows/ci.yml)

**`b53-go`** — Go-библиотека и CLI без внешних зависимостей для обратимого криптографического шифрования булевых срезов (`[]bool`) произвольной длины в стандартные 64-битные числа с плавающей точкой (`IEEE 754 binary64` / `float64`) на полуинтервале $[0.0, 1.0)$.

Библиотека полностью совместима по бинарному формату, цепочкам чанков и ключевой функции `scrypt` с Python-библиотекой [`b53`](https://github.com/1orgar/b53).

## Ключевые свойства

- **Скрытая размерность внутри числа:** для массивов длиной $L \in [1, 50]$ длина кодируется непосредственно в 53-битном пространстве мантиссы без передачи внешних метаданных.
- **Случайная компонента (Nonce) при каждой генерации:** повторное шифрование одного и того же массива с одной и той же солью даёт разные псевдослучайные `float64`.
- **Биективная 53-битная перестановка:** 8-раундовая несбалансированная сеть Фейстеля ($26 + 27 = 53$ бита) с раундовой функцией на базе `HMAC-SHA256` и секретной соли.
- **Сериализация произвольной длины с цепочкой солей:** `Serialize` / `Deserialize` разбивают срез любой длины на `(len / minSize) + 1` случайных чанков и связывают их через цепочку `HMAC-SHA256` seed-ключей.
- **Встроенный `scrypt` KDF (RFC 7914):** `DeriveSalt` и `NewCipherFromPassword` преобразуют пароль в 256-битную соль с поддержкой контекста.
- **Только стандартная библиотека Go 1.22+:** ноль внешних зависимостей, потокобезопасный `Cipher`.

## Установка

Библиотека:

```bash
go get github.com/1orgar/b53-go
```

CLI-утилита:

```bash
go install github.com/1orgar/b53-go/cmd/b53@latest
```

## Быстрый старт

### Go API

```go
package main

import (
	"fmt"
	"log"

	"github.com/1orgar/b53-go"
)

func main() {
	// 1. Генерация 256-битной соли-ключа (или key stretching из пароля через scrypt)
	salt, err := b53.GenerateSalt(b53.DefaultSaltBytes)
	if err != nil {
		log.Fatal(err)
	}
	// salt, err = b53.DeriveSalt("my-passphrase", b53.WithContext("user:42"))

	// 2. Шифрование []bool (1..50 элементов) в float64 на [0.0, 1.0)
	bits := []bool{true, false, true, true, false, false, true, false, true, true}
	x1, err := b53.Encrypt(bits, salt)
	if err != nil {
		log.Fatal(err)
	}
	x2, err := b53.Encrypt(bits, salt) // разный результат за счёт случайного nonce
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("distinct:", x1 != x2)

	// 3. Однозначное восстановление среза и его длины
	restored, err := b53.Decrypt(x1, salt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(b53.FormatBits(restored)) // 1011001011

	// 4. Сериализация и десериализация []bool произвольной длины в []float64
	manyBits := make([]bool, 250)
	for i := range manyBits {
		manyBits[i] = i%3 == 0
	}
	doubles, err := b53.Serialize(manyBits, salt, b53.WithMinSize(10))
	if err != nil {
		log.Fatal(err)
	}
	recoveredMany, err := b53.Deserialize(doubles, salt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("chunks:", len(doubles), "matched:", b53.FormatBits(recoveredMany) == b53.FormatBits(manyBits))
}
```

Для многократных операций с одной солью (включая конкурентный доступ из горутин) используйте `Cipher`:

```go
cipher, err := b53.NewCipher(salt) // принимает hex-строку, UTF-8 фразу или []byte
// или: cipher, err := b53.NewCipherFromPassword("my-passphrase", b53.WithContext("tenant-a"))
if err != nil {
	log.Fatal(err)
}

encoded, err := cipher.EncryptString("1011001011")
if err != nil {
	log.Fatal(err)
}
fmt.Println(encoded)
fmt.Println(cipher.DecryptString(encoded)) // "1011001011"

doubles, err := cipher.Serialize(manyBits) // по умолчанию minSize = 10
if err != nil {
	log.Fatal(err)
}
restoredMany, err := cipher.Deserialize(doubles)
```

### CLI

```bash
# 1. Генерация соли (или выведение из пароля через scrypt)
SALT=$(b53 generate-salt)
# SALT=$(b53 derive-salt "my-passphrase" --context "user:42")

# 2. Три независимых шифрования одного массива
b53 encrypt 1011001011 --salt "$SALT" --count 3

# 3. Дешифрование
b53 decrypt 0.29004509923272503 --salt "$SALT"

# 4. Сериализация и десериализация произвольной длины
CHUNKS=$(b53 serialize 10110010110101010101110011001 --salt "$SALT" --min-size 10 -q | paste -sd, -)
b53 deserialize "$CHUNKS" --salt "$SALT"
```

Поддерживаются `--salt-file`, переменная окружения `B53_SALT` и флаг `-q` / `--quiet`.

## Математическая модель

Число на равномерной сетке $[0.0, 1.0)$ имеет вид $x = C \cdot 2^{-53}$, где $C \in \{0, 1, \dots, 2^{53} - 1\}$.

Всё пространство из $2^{53} = 9\,007\,199\,254\,740\,992$ состояний без остатка разбивается на 50 непересекающихся сегментов для $L \in [1, 50]$:

$$\sum_{L=1}^{50} M_L \cdot 2^L = 2^{53}$$

Бюджет распределяется адаптивно сверху вниз от $L = 50$ к $L = 1$ (около 25% остатка на шаг, не менее $M_L \ge 3$ вариантов на границе $L = 50$):

| Длина массива $L$ | Комбинаций ($2^L$) | Вариантов nonce ($M_L$) | Размер сегмента ($M_L \cdot 2^L$) |
|---:|---:|---:|---:|
| 50 | $2^{50}$ | 3 | $3 \times 2^{50}$ |
| 49 | $2^{49}$ | 3 | $3 \times 2^{49}$ |
| 48 | $2^{48}$ | 3 | $3 \times 2^{48}$ |
| 47 | $2^{47}$ | 5 | $5 \times 2^{47}$ |
| 45 | $2^{45}$ | 13 | $13 \times 2^{45}$ |
| 40 | $2^{40}$ | 100 | $100 \times 2^{40}$ |
| 30 | $2^{30}$ | 5 811 | $5\,811 \times 2^{30}$ |
| 20 | $2^{20}$ | 335 103 | $335\,103 \times 2^{20}$ |
| 10 | $2^{10}$ | 19 323 738 | $\approx 1{,}98 \times 10^{10}$ |
| 1 | $2^1$ | 2 971 477 630 | $\approx 5{,}94 \times 10^9$ |

## Требования к хранению и передаче `float64`

- При передаче через текст, CLI, CSV или JSON обязательно сохраняйте точность (`strconv.FormatFloat(x, 'g', -1, 64)` / стандартный `encoding/json`, в PostgreSQL — бинарный тип `DOUBLE PRECISION` / `FLOAT8`). Округление даже последнего разряда разрушает младшие биты шифротекста.
- При использовании `Serialize` / `Deserialize` порядок и полный состав среза `[]float64` должны сохраняться целиком: начальный seed привязан к количеству чанков, а каждый последующий чанк шифруется модифицированной солью от предыдущего seed, индекса и размера предыдущего чанка — расшифровать отдельный `float64` по отдельности невозможно.

## Разработка и тесты

```bash
go vet ./...
go test -v -race ./...
go build ./cmd/b53
```

## Лицензия

[MIT](LICENSE)
