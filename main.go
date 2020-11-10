package main

import (
	"./client"
	"./datastruc"
	"./server"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"fmt"
	"log"
	"time"
)

type ClienKeys struct {
	Clienprivks map[int]*ecdsa.PrivateKey
	Clientpubkstrs map[int]string
}

func main() {
	ck := ClienKeys{}
	ck.Clienprivks = make(map[int]*ecdsa.PrivateKey)
	ck.Clientpubkstrs = make(map[int]string)
	for i:=0; i<100; i++ {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
		if err != nil {
			log.Fatalln(err)
		}
		ck.Clienprivks[i] = privateKey
		pubkey := &privateKey.PublicKey
		ck.Clientpubkstrs[i] = datastruc.EncodePublic(pubkey)
	}

	inittotalserver := 4
	for i:=0; i<inittotalserver; i++ {
		theserver := server.CreateServer(i, inittotalserver, ck.Clientpubkstrs)
		go theserver.Start()
	}
	lateserver := 0 // 机制1测试
	for i:=0; i<lateserver; i++ {
		theserver := server.CreateLateServer(inittotalserver+i)
		go theserver.LateStart(ck.Clientpubkstrs, 5+2*i) // new nodes join serially
	}

	time.Sleep(time.Second * 1)

	for i:=20; i<40; i++ {
		theclient := client.CreateClient(i, inittotalserver+lateserver, ck.Clienprivks[i])
		go theclient.Run()
	}

	time.Sleep(time.Second * 60)
	fmt.Println("main thread completes")
}
