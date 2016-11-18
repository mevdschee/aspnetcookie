package aspnetcookie

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"strings"
	"time"

	"unicode/utf16"
)

func newTicket(name string, ttl int64, isPersistent bool, userData, cookiePath string) *FormsAuthenticationTicket {
	t := &FormsAuthenticationTicket{
		version:           2,
		name:              name,
		issueDateUtc:      time.Now().UTC().Unix(),
		expirationDateUtc: ttl,
		isPersistent:      isPersistent,
		userData:          userData,
		cookiePath:        cookiePath,
	}
	t.expirationDateUtc = t.expirationDateUtc + t.issueDateUtc
	return t
}

func fromUnixTime(v int64) uint64 {
	return uint64(v)*10000000 + 621355968000000000
}

func toUnixTime(v uint64) int64 {
	return int64((v - 621355968000000000) / 10000000)
}

// FormsAuthenticationTicket holds:
type FormsAuthenticationTicket struct {
	version           byte
	name              string
	issueDateUtc      int64
	expirationDateUtc int64
	isPersistent      bool
	userData          string
	cookiePath        string
}

func uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	for p := 0; p < 8; p++ {
		b[p] = byte(v & 255)
		v = v >> 8
	}
	return b
}

func uint64FromBytes(b []byte) uint64 {
	v := uint64(0)
	for p := 0; p < 8; p++ {
		v = v << 8
		v = v | uint64(b[7-p])
	}
	return v
}

func boolToByte(v bool) byte {
	var b byte
	if v {
		b = 1
	}
	return b
}

func boolFromByte(v byte) bool {
	var b bool
	if v == 0x01 {
		b = true
	}
	return b
}

func intToBytes(v int, b *bytes.Buffer) {
	if v == 0 {
		b.WriteByte(byte(v))
	} else {
		for v > 0 {
			c := byte(v) & 127
			if v > 127 {
				c = c | 128
			}
			b.WriteByte(c)
			v = v >> 7
		}
	}
}

func intFromBytes(b *bytes.Buffer) int {
	var res int
	var n int
	var c byte
	for ok := true; ok; ok = c&128 > 0 {
		c, _ = b.ReadByte()
		res = res | (int(c&0x7f) << uint(7*n))
		n++
	}
	return res
}

func stringToBytes(s string, b *bytes.Buffer) error {
	str := utf16.Encode([]rune(s))
	intToBytes(len(str), b)
	for _, c := range str {
		b.WriteByte(byte(c))
		c = c >> 8
		b.WriteByte(byte(c))
	}
	return nil
}

func stringFromBytes(b *bytes.Buffer) (string, error) {
	s := intFromBytes(b)
	str := make([]uint16, s)
	for i := 0; i < s; i++ {
		b1, _ := b.ReadByte()
		b2, _ := b.ReadByte()
		str[i] = uint16(b1) | (uint16(b2) << 8)
	}
	return string(utf16.Decode(str)), nil
}

// Serialize is
func (t *FormsAuthenticationTicket) Serialize() ([]byte, error) {
	var err error
	var b bytes.Buffer
	b.WriteByte(0x01)
	b.WriteByte(t.version)
	b.Write(uint64ToBytes(fromUnixTime(t.issueDateUtc)))
	b.WriteByte(0xfe)
	b.Write(uint64ToBytes(fromUnixTime(t.expirationDateUtc)))
	b.WriteByte(boolToByte(t.isPersistent))
	err = stringToBytes(t.name, &b)
	if err != nil {
		return nil, err
	}
	err = stringToBytes(t.userData, &b)
	if err != nil {
		return nil, err
	}
	err = stringToBytes(t.cookiePath, &b)
	if err != nil {
		return nil, err
	}
	b.WriteByte(0xff)
	return b.Bytes(), nil
}

// Deserialize is
func (t *FormsAuthenticationTicket) Deserialize(buf []byte) (int, error) {
	var err error
	b := bytes.NewBuffer(buf)
	if c, _ := b.ReadByte(); c != 0x01 {
		return len(buf) - b.Len(), errors.New("expected 0x01")
	}
	t.version, _ = b.ReadByte()
	t.issueDateUtc = toUnixTime(uint64FromBytes(b.Next(8)))
	if c, _ := b.ReadByte(); c != 0xfe {
		return len(buf) - b.Len(), errors.New("expected 0xfe")
	}
	t.expirationDateUtc = toUnixTime(uint64FromBytes(b.Next(8)))
	t.isPersistent = boolFromByte(b.Next(1)[0])
	if t.name, err = stringFromBytes(b); err != nil {
		return len(buf) - b.Len(), err
	}
	if t.userData, err = stringFromBytes(b); err != nil {
		return len(buf) - b.Len(), err
	}
	if t.cookiePath, err = stringFromBytes(b); err != nil {
		return len(buf) - b.Len(), err
	}
	if c, _ := b.ReadByte(); c != 0xff {
		return len(buf) - b.Len(), errors.New("expected 0xff")
	}
	return len(buf) - b.Len(), nil
}

// New returns a new AspNetCookie.
func New(hashName string, hashKey []byte, blockName string, blockKey []byte) *AspNetCookie {
	hashFunctions := map[string]func() hash.Hash{
		"SHA1": sha1.New,
	}
	blockCiphers := map[string]func([]byte) (cipher.Block, error){
		"AES": aes.NewCipher,
		"NIL": nil,
	}
	hashFunction, ok := hashFunctions[strings.ToUpper(hashName)]
	if !ok {
		hashFunction = hashFunctions["SHA1"]
	}
	blockCipher, ok := blockCiphers[strings.ToUpper(blockName)]
	if !ok || blockKey == nil {
		blockCipher = blockCiphers["NIL"]
	}
	c := &AspNetCookie{
		hashFunc: hashFunction,
		hashKey:  hashKey,
		block:    blockCipher,
		blockKey: blockKey,
	}
	return c
}

// AspNetCookie encodes and decodes authenticated and encrypted cookie values
// holding a FormsAuthenticationTicket.
type AspNetCookie struct {
	hashKey  []byte
	hashFunc func() hash.Hash
	blockKey []byte
	block    func([]byte) (cipher.Block, error)
}

// EncodeNew encodes a cookie value.
func (s *AspNetCookie) EncodeNew(name string, ttl int64, isPersistent bool, userData, cookiePath string) ([]byte, error) {
	return s.Encode(newTicket(name, ttl, isPersistent, userData, cookiePath))
}

// Encode encodes a cookie value.
func (s *AspNetCookie) Encode(value *FormsAuthenticationTicket) ([]byte, error) {
	var err error
	var b, rnd []byte
	var buf bytes.Buffer
	var block cipher.Block
	// start with 16 bytes of random data
	rnd, _ = GenerateRandomKey(16)
	buf.Write(rnd)
	// serialize ticket
	if b, err = value.Serialize(); err != nil {
		return nil, err
	}
	// create and append MAC
	mac := createMac(hmac.New(s.hashFunc, s.hashKey), b)
	b = append(b, mac...)
	// encrypt (optional)
	if s.block != nil {
		// create cipher
		block, err = s.block(s.blockKey)
		if err != nil {
			return nil, err
		}
		// add padding to fill the block
		end := ((len(b) + block.BlockSize()) / block.BlockSize()) * block.BlockSize()
		pad := end - len(b)
		padding := make([]byte, pad)
		for i := 0; i < pad; i++ {
			padding[i] = byte(pad)
		}
		b = append(b, padding...)
		// encrypt
		if b, err = encrypt(block, b); err != nil {
			return nil, err
		}
	}
	buf.Write(b)
	// add some random data
	rnd, _ = GenerateRandomKey(16)
	buf.Write(rnd)
	// return result
	return buf.Bytes(), nil
}

// Decode decodes a cookie value.
func (s *AspNetCookie) Decode(b []byte) (*FormsAuthenticationTicket, error) {
	var err error
	dst := &FormsAuthenticationTicket{}
	// remove first and last 16 bytes random data
	b = b[16 : len(b)-16]
	// decrypt (optional)
	if s.block != nil {
		block, err := s.block(s.blockKey)
		if err != nil {
			return nil, err
		}
		end := (len(b) / block.BlockSize()) * block.BlockSize()
		if b, err = decrypt(block, b[:end]); err != nil {
			return nil, err
		}
	}
	// deserialize
	var pos int
	if pos, err = dst.Deserialize(b); err != nil {
		return nil, err
	}
	// verify MAC
	h := hmac.New(s.hashFunc, s.hashKey)
	if err = verifyMac(h, b[0:pos], b[pos:pos+h.Size()]); err != nil {
		return nil, err
	}
	pos = pos + h.Size()
	// verify padding
	if s.block != nil {
		pad := b[pos]
		for i := 0; i < int(pad); i++ {
			if b[pos+i] != pad {
				return nil, errors.New("invalid padding")
			}
		}
	}
	// return result
	return dst, nil
}

// Authentication -------------------------------------------------------------

// createMac creates a message authentication code (MAC).
func createMac(h hash.Hash, value []byte) []byte {
	h.Write(value)
	return h.Sum(nil)
}

// verifyMac verifies that a message authentication code (MAC) is valid.
func verifyMac(h hash.Hash, value []byte, mac []byte) error {
	mac2 := createMac(h, value)
	// Check that both MACs are of equal length, as subtle.ConstantTimeCompare
	// does not do this prior to Go 1.4.
	if len(mac) == len(mac2) && subtle.ConstantTimeCompare(mac, mac2) == 1 {
		return nil
	}
	return errors.New("invalid mac")
}

// Encryption -----------------------------------------------------------------

// encrypt encrypts a value using the given block in counter mode.
func encrypt(block cipher.Block, value []byte) ([]byte, error) {
	iv, err := GenerateRandomKey(block.BlockSize())
	if err != nil {
		return nil, err
	}
	// Encrypt it.
	stream := cipher.NewCBCEncrypter(block, iv)
	stream.CryptBlocks(value, value)
	// Return iv + ciphertext.
	return append(iv, value...), nil
}

// decrypt decrypts a value using the given block in counter mode.
func decrypt(block cipher.Block, value []byte) ([]byte, error) {
	size := block.BlockSize()
	if len(value) > size {
		// Extract iv.
		iv := value[:size]
		// Extract ciphertext.
		value = value[size:]
		// Decrypt it.
		stream := cipher.NewCBCDecrypter(block, iv)
		stream.CryptBlocks(value, value)
		return value, nil
	}
	return nil, errors.New("decryption failed")
}

// Helpers --------------------------------------------------------------------

// GenerateRandomKey creates a random key with the given length in bytes.
func GenerateRandomKey(length int) ([]byte, error) {
	k := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}
