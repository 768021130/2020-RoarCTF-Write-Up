package main

import (
	"bytes"
	"flag"
	"image"
	"image/color"
	"image/png"
	"io/ioutil"
	"math/rand"
	"os"
)

var input_filename = flag.String("i", "", "")
var message_filename = flag.String("f", "", "")

var lsbyte_mask uint32 = ^(uint32(255))

var byte_buffer_len = 256

const (
	rounds128 = 68
)
const (
	s2 = 0x7369f885192c0ef5
)

type MyCipher struct {
	k      []uint64
	rounds int
}

func leToU64(b []byte) uint64 {
	r := uint64(0)
	for i := uint(0); i < 8; i++ {
		r |= uint64(b[i]) << (8 * i)
	}
	return r
}

func leU64(dst []byte, n uint64) {
	for i := uint(0); i < 8; i++ {
		dst[i] = byte(n >> (8 * i))
	}
}

func leftRotate64(n uint64, shift uint) uint64 {
	return (n << shift) | (n >> (64 - shift))
}

func ror(n uint64, shift uint) uint64 {
	return leftRotate64(n, 64-shift)
}

func NewCipher(key []byte) *MyCipher {
	cipher := new(MyCipher)
	var keyWords int
	var z uint64

	switch len(key) {
	case 16:
		keyWords = 2
		z = s2
		cipher.rounds = rounds128
	default:
		panic("key error")
	}
	cipher.k = make([]uint64, cipher.rounds)
	for i := 0; i < keyWords; i++ {
		cipher.k[i] = leToU64(key[8*i : 8*i+8])
	}
	for i := keyWords; i < cipher.rounds; i++ {
		tmp := ror(cipher.k[i-1], 3)
		if keyWords == 4 {
			tmp ^= cipher.k[i-3]
		}
		tmp ^= ror(tmp, 1)
		lfsrBit := (z >> uint((i-keyWords)%62)) & 1
		cipher.k[i] = ^cipher.k[i-keyWords] ^ tmp ^ uint64(lfsrBit) ^ 3
	}
	return cipher
}

func (cipher *MyCipher) BlockSize() int {
	return 16
}

func s64(x uint64) uint64 {
	return (leftRotate64(x, 1) & leftRotate64(x, 8)) ^ leftRotate64(x, 2)
}

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory. See crypto/cipher.
func (cipher *MyCipher) enc(dst, src []byte) {
	y := leToU64(src[0:8])
	x := leToU64(src[8:16])
	for i := 0; i < cipher.rounds; i++ {
		x, y = y^s64(x)^cipher.k[i], x
	}
	leU64(dst[0:8], y)
	leU64(dst[8:16], x)
}

func (cipher *MyCipher) dec(dst, src []byte) {
	y := leToU64(src[0:8])
	x := leToU64(src[8:16])
	for i := cipher.rounds - 1; i >= 0; i-- {
		x, y = y, x^s64(y)^cipher.k[i]
	}
	leU64(dst[0:8], y)
	leU64(dst[8:16], x)
}
func bytesCombine(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}
func readImageFile() (image.Image, error) {
	input_reader, err := os.Open(*input_filename)
	if err != nil {
		return nil, err
	}
	defer input_reader.Close()

	img, _, err := image.Decode(input_reader)

	return img, err
}

func encColor(mb byte, c uint32) uint32 {
	newc := c
	newc = uint32(mb) + (c & lsbyte_mask)

	return newc
}

func decColor(c uint32) (byte, error) {
	return byte(c & ^lsbyte_mask), nil
}
func pad(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func main() {
	flag.Parse()

	img, err := readImageFile()
	if err != nil {
		panic(err)
		return
	}

	var hidemsg_len uint32 = 0
	var message_index uint32 = 0

	bounds := img.Bounds()
	var size = bounds.Dx() * bounds.Dy()
	println(size)
	var out = make([]byte, 0)

	rand.Seed((int64)(size))
	var shuf = rand.Perm(size)
	println(shuf[0])
	println(shuf[1])
	println(shuf[2])

OUTER:
	for p := 0; p < size; p += 4 {
		var x = shuf[p/4] % bounds.Dx()
		var y = shuf[p/4] / bounds.Dx()
		c := img.At(x, y).(color.NRGBA64)
		if p == 0 {
			hidemsg_len = (uint32(c.R) & ^lsbyte_mask) << 24
			hidemsg_len += (uint32(c.G) & ^lsbyte_mask) << 16
			hidemsg_len += (uint32(c.B) & ^lsbyte_mask) << 8
			hidemsg_len += (uint32(c.A) & ^lsbyte_mask)
			println(hidemsg_len)

		} else {

			ch, _ := decColor(uint32(c.R))
			message_index++
			if message_index > hidemsg_len {
				break OUTER
			}
			out = append(out, ch)

			ch, _ = decColor(uint32(c.G))
			message_index++
			if message_index > hidemsg_len {
				break OUTER
			}
			out = append(out, ch)

			ch, _ = decColor(uint32(c.B))
			message_index++
			if message_index > hidemsg_len {
				break OUTER
			}
			out = append(out, ch)

			ch, _ = decColor(uint32(c.A))
			message_index++
			if message_index > hidemsg_len {
				break OUTER
			}
			out = append(out, ch)
		}
	}

	kkey := make([]byte, 16)
	for i := 0; i < 16; i += 1 {
		kkey[i] = byte(size % (i + 1))
	}
	c := NewCipher(kkey)
	for i := 0; i < len(out); i += 16 {
		c.dec(out[i:i+16], out[i:i+16])
	}
	ioutil.WriteFile(*message_filename, out, 0666)
	var test = false
	if test {
		output_image := image.NewNRGBA64(img.Bounds())
		output_writer, err := os.Create(*message_filename)
		png.Encode(output_writer, output_image)
		if err != nil {
			return
		}
	}
}
