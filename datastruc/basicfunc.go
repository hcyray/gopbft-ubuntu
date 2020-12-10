package datastruc

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"log"
	"os"
	"strconv"
)
import "fmt"

func TwoHashEqual(a [32]byte, b [32]byte) bool {
	for i:=0; i<32; i++ {
		if a[i]!=b[i] {
			return false
		}
	}
	return true
}

func Takemax(a, b int) int {
	res := a
	if b>a {
		res = b
	}
	return res
}

func Takemin(a, b int) int {
	res := a
	if b<a {
		res = b
	}
	return res
}

func SingleHash256(a *[]byte, b *[32]byte) {
	*b = sha256.Sum256(*a)
	//*b = sha256.Sum256(tmp[:])
}

func CommandToBytes(command string) []byte {
	//command -> byte
	var bytees [commandLength]byte
	for i, c := range command {
		bytees[i] = byte(c)
	}
	return bytees[:]
}

func BytesToCommand(bytees []byte) string {
	//byte -> command
	var command []byte
	for _, b := range bytees {
		if b != 0x0 {
			command = append(command, b)
		}
	}
	return fmt.Sprintf("%s", command)
}

func GenerateSystemHash(ver, height int, confighash, utxohash, cdestatehash [32]byte) [32]byte {
	var res [32]byte
	data := []byte(strconv.Itoa(ver)+","+strconv.Itoa(height)+","+string(confighash[:])+","+string(utxohash[:])+","+string(cdestatehash[:]))
	res = sha256.Sum256(data)
	return res
}

//func RecordConfig(sl *SuccLine) {
//	file, err := os.OpenFile("config", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
//	if err!=nil {
//		fmt.Println("create config file error")
//	}
//	enc := gob.NewEncoder(file)
//	err = enc.Encode(sl.Serialize())
//	if err!=nil {
//		fmt.Println("write config to file error")
//	}
//}

func ReadConfig() []PeerIdentity {
	// read from some existing instance

	var conten []byte
	file, err := os.Open("config")
	if err!=nil {
		fmt.Println("read file error")
	}
	dec := gob.NewDecoder(file)
	err = dec.Decode(&conten)

	var sllist []PeerIdentity
	var buff bytes.Buffer
	buff.Write(conten)
	decc := gob.NewDecoder(&buff)
	err = decc.Decode(&sllist)
	if err!=nil {
		log.Panic(err)
	}
	return sllist
}

func HashEqualDefault(thehash [32]byte) bool {
	res := true

	for i:=0; i<32; i++ {
		if thehash[i]!=0 {
			res = false
			break
		}
	}

	return res
}

func GenerateTwoBitId(id int) string {
	res := ""
	if id<10 {
		res = "0" + strconv.Itoa(id)
	} else {
		res = strconv.Itoa(id)
	}
	return res
}

func EncodeBool(current *[]byte, d bool) error {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, d)
	if err != nil {
		return fmt.Errorf("Basic.EncodeInt write failed, %s", err)
	}
	*current = append(*current, buf.Bytes()...)
	return nil
}

func EncodeInt(current *[]byte, d int) error {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, d)
	if err != nil {
		return fmt.Errorf("Basic.EncodeInt write failed, %s", err)
	}
	*current = append(*current, buf.Bytes()...)
	return nil
}

func EncodeUint64(current *[]byte, d uint64) error {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, d)
	if err != nil {
		return fmt.Errorf("Basic.EncodeInt write failed, %s", err)
	}
	*current = append(*current, buf.Bytes()...)
	return nil
}

func EncodeString(current *[]byte, d string) error {
	dstr := []byte(d)
	*current = append(*current, dstr...)
	return nil
}

func EncodeByteSlice(current *[]byte, d []byte) error {
	*current = append(*current, d...)
	return nil
}