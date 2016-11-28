package aspnetcookie

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDecode7BitInt(t *testing.T) {
	const data = "\x88\x03"
	b := bytes.NewBufferString(data)
	i := intFromBytes(b)
	n := len(data) - b.Len()
	if n != 2 {
		t.Fatalf("Decoding '88 03' as 7bit int. Expected length '2', got '%d'", n)
	}
	if i != 392 {
		t.Fatalf("Decoding '88 03' as 7bit int. Expected '392', got '%d'", i)
	}
}

func TestEncode7BitInt(t *testing.T) {
	const data = "\x88\x03"
	var b bytes.Buffer
	intToBytes(392, &b)
	written := string(b.Bytes())
	if written != data {
		t.Fatalf("Encoding '392' as 7bit int. Expected '88 03', got '% x'", written)
	}
}

func Test7BitIntRange(t *testing.T) {
	var b bytes.Buffer
	for i := 0; i < 30000; i = i + 100 {
		b.Reset()
		intToBytes(i, &b)
		j := intFromBytes(&b)
		if i != j {
			t.Fatalf("Doing '%d' as 7bit int and reverse. Expected '%d', got '%d'", i, i, j)
		}
	}
}

func Test7BitIntNull(t *testing.T) {
	const data = "\x00"
	var b bytes.Buffer
	intToBytes(0, &b)
	written := string(b.Bytes())
	if written != data {
		t.Fatalf("Encoding '0' as 7bit int. Expected '00', got '% x'", written)
	}
}

func TestStringFromBytes(t *testing.T) {
	const data = "\x02\x24\x00\xAC\x20"
	const ref = "$€"
	b := bytes.NewBufferString(data)
	str, _ := stringFromBytes(b)
	if str != ref {
		t.Fatalf("Decoding '% x' as UTF16LE string with 7bit int length. Expected '%s', got '%s'", data, ref, str)
	}
}

func TestStringFromBytesSurrogatePairs(t *testing.T) {
	const data = "\x04\x01\xD8\x37\xDC\x52\xD8\x62\xDF"
	const ref = "𐐷𤭢"
	b := bytes.NewBufferString(data)
	str, _ := stringFromBytes(b)
	if str != ref {
		t.Fatalf("Decoding '% x' as UTF16LE string with 7bit int length. Expected '% x', got '% x'", data, ref, str)
	}
}

func TestStringToBytes(t *testing.T) {
	const data = "$€"
	const ref = "\x02\x24\x00\xAC\x20"
	var b bytes.Buffer
	stringToBytes(data, &b)
	str := string(b.Bytes())
	if str != ref {
		t.Fatalf("Encoding '%s' as UTF16LE string with 7bit int length. Expected '% x', got '% x'", data, ref, str)
	}
}

func TestStringToBytesSurrogatePairs(t *testing.T) {
	const data = "𐐷𤭢"
	const ref = "\x04\x01\xD8\x37\xDC\x52\xD8\x62\xDF"
	var b bytes.Buffer
	stringToBytes(data, &b)
	str := string(b.Bytes())
	if str != ref {
		t.Fatalf("Encoding '% x' as UTF16LE string with 7bit int length. Expected '% x', got '% x'", data, ref, str)
	}
}

func TestDecodeCookie(t *testing.T) {
	validationKey, _ := hex.DecodeString("2E502E08392C704E2234759EDA7A5940A8CE1C42C7964B8142778764CF0006C23418F4E174BFFF4E742C80CF0B47DCC6DA5BB5420B6F72A9670AEF27C18D5769")
	decryptionKey, _ := hex.DecodeString("5226859B3CB262982B574093B29DAD9083030C93604C820F009D5192BDEC31F2")
	a := New("SHA1", validationKey, "AES", decryptionKey)
	cookie, _ := hex.DecodeString("29965C40C4ABD106292507EA84DB864371C60730E3B492EB11BDF18AEF627C46E7D56DC0F5D1F55562A04901E608F5582B9E92CCCB083D99449665BC6F8DB8B6A706B49CBD06B8C74D7606FEA81E4B52941AD72F311D4C6349B132B79BDE2E5B7D74A5CD9606E31DDDEEDE27E385BF2702E3A7F8035182DF1756F91C1CFF7FA772C0DBE7C2C56085FD7D735B73BFFCD5C42CB153D66FC54365D5E2BB8A2A3473")
	ticket, err := a.Decode(cookie)
	if err != nil {
		t.Fatalf("Error while decoding, got '%v'", err)
	}
	if ticket == nil {
		t.Fatal("Error while decoding, got nil ticket")
	}
	if ticket.name != "maurits.vanderschee" {
		t.Fatalf("Expected 'ticket.username' to be 'maurits.vanderschee', got '%s'", ticket.name)
	}
}

func TestEncodeDecodeCookie(t *testing.T) {
	validationKey, _ := hex.DecodeString("2E502E08392C704E2234759EDA7A5940A8CE1C42C7964B8142778764CF0006C23418F4E174BFFF4E742C80CF0B47DCC6DA5BB5420B6F72A9670AEF27C18D5769")
	decryptionKey, _ := hex.DecodeString("5226859B3CB262982B574093B29DAD9083030C93604C820F009D5192BDEC31F2")
	a := New("SHA1", validationKey, "AES", decryptionKey)
	cookie, _ := a.EncodeNew("maurits.vanderschee", 3600*24*365, true, "\"nothing\"", "/")
	ticket, _ := a.Decode(cookie)
	if ticket.name != "maurits.vanderschee" {
		t.Fatalf("Expected 'ticket.username' to be 'maurits.vanderschee', got '%s'", ticket.name)
	}
}
