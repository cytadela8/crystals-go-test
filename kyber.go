package main

import (
	"fmt"
	dilithium "github.com/kudelskisecurity/crystals-go/crystals-dilithium"
	"github.com/kudelskisecurity/crystals-go/crystals-kyber"
)

func Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func BitFlipKyber(sk, c, ss []byte, k *kyber.Kyber) {
	cCopy := make([]byte, len(c))
	copy(cCopy, c)
	ok := 0
	fail := 0
	for i := 0; i < len(c); i++ {
		for p := 0; p < 8; p++ {
			cCopy[i] = c[i] ^ (1 << p)
			ssFlip := k.Decaps(sk, cCopy)
			if Equal(ss, ssFlip) {
				fmt.Println("Found!!!")
				fail++
			} else {
				ok++
			}
		}
		cCopy[i] = c[i]
	}
	fmt.Printf("ok=%d, fail=%d\n", ok, fail)
}

func TestKyber(k *kyber.Kyber) {
	seed1 := make([]byte, 64)
	pk, sk := k.KeyGen(seed1)
	//fmt.Printf("pk=%X\nsk=%X\n", pk, sk)
	seed2 := make([]byte, 32)
	c, ss := k.Encaps(pk, seed2)
	ss2 := k.Decaps(sk, c)
	//fmt.Printf("c=%X\nss=%X\n", c, ss)
	fmt.Printf("ok?=%t\n", Equal(ss, ss2))
	BitFlipKyber(sk, c, ss, k)
	biggerby1 := make([]byte, len(c)+1)
	copy(biggerby1, c)
	fmt.Printf("bigger by 1=%X\n", k.Decaps(sk, biggerby1))
	smallerby1 := make([]byte, len(c)-1)
	copy(biggerby1, c)
	fmt.Printf("smaller by 1=%X\n", k.Decaps(sk, smallerby1))
}

func BitFlipMsg(pk, msg, sig []byte, d *dilithium.Dilithium) {
	msgCopy := make([]byte, len(msg))
	copy(msgCopy, msg)
	ok := 0
	fail := 0
	for i := 0; i < len(msg); i++ {
		for p := 0; p < 8; p++ {
			msgCopy[i] = msg[i] ^ (1 << p)
			if d.Verify(pk, msgCopy, sig) {
				fmt.Println("Found!!!")
				fail++
			} else {
				ok++
			}
		}
		msgCopy[i] = msg[i]
	}
	fmt.Printf("[flipMsg] ok=%d, fail=%d\n", ok, fail)
}

func BitFlipSig(pk, msg, sig []byte, d *dilithium.Dilithium) {
	sigCopy := make([]byte, len(sig))
	copy(sigCopy, sig)
	ok := 0
	fail := 0
	for i := 0; i < len(sig); i++ {
		for p := 0; p < 8; p++ {
			sigCopy[i] = sig[i] ^ (1 << p)
			if d.Verify(pk, msg, sigCopy) {
				fmt.Println("Found!!!")
				fail++
			} else {
				ok++
			}
		}
		sigCopy[i] = sig[i]
	}
	fmt.Printf("[flipSig] ok=%d, fail=%d\n", ok, fail)
}

func TestDilithium(d *dilithium.Dilithium) {
	seed1 := make([]byte, 32)
	pk, sk := d.KeyGen(seed1)
	msg := []byte("This is a messageThis is a message")
	sig := d.Sign(sk, msg)
	fmt.Printf("verify?=%t\n", d.Verify(pk, msg, sig))
	BitFlipMsg(pk, msg, sig, d)
	BitFlipSig(pk, msg, sig, d)
	msgCopySmall := make([]byte, len(msg)-1)
	copy(msgCopySmall, msg)
	fmt.Printf("verifySmall?=%t\n", d.Verify(pk, msgCopySmall, sig))
	msgCopyBig := make([]byte, len(msg)+1)
	copy(msgCopyBig, msg)
	fmt.Printf("verifyBig?=%t\n", d.Verify(pk, msgCopyBig, sig))
}

func main() {
	fmt.Println("Kyber512")
	TestKyber(kyber.NewKyber512())
	fmt.Println("Kyber768")
	TestKyber(kyber.NewKyber768())
	fmt.Println("Kyber1024")
	TestKyber(kyber.NewKyber1024())
	fmt.Println("---Dilithium2---")
	TestDilithium(dilithium.NewDilithium2(false))
	fmt.Println("---Dilithium3---")
	TestDilithium(dilithium.NewDilithium3(false))
	fmt.Println("---Dilithium5---")
	TestDilithium(dilithium.NewDilithium5(false))
}
