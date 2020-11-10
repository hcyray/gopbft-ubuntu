package client

import (
	"../datastruc"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"time"
)

type Client struct {
	id int
	miners []int
	minerIPAddress      map[int]string

	sendtxCh chan datastruc.Datatosend

	nodePubKey *ecdsa.PublicKey
	nodePrvKey *ecdsa.PrivateKey
	nodePubkeystr string
	nodePrvkeystr string
}

func CreateClient(id int, servernum int, privateKey *ecdsa.PrivateKey) *Client {
	client := &Client{}
	client.id = id
	client.miners = make([]int, servernum)
	client.minerIPAddress = make(map[int]string)
	client.generateServerOrderIp(servernum)
	client.sendtxCh = make(chan datastruc.Datatosend)

	publicKey := &privateKey.PublicKey
	client.nodePrvKey = privateKey
	client.nodePubKey = publicKey
	client.nodePrvkeystr = datastruc.EncodePrivate(privateKey)
	client.nodePubkeystr = datastruc.EncodePublic(publicKey)
	//fmt.Println("client", client.id, "pubkey length is", len(client.nodePubkeystr))
	return client
}

func (client *Client) generateServerOrderIp(servnum int) {
	id := client.id
	for i:=0; i<servnum; i++ {
		var theip string
		if id<10 {
			theip = ipprefix + strconv.Itoa(i) + "0" + strconv.Itoa(id)
		} else {
			theip = ipprefix + strconv.Itoa(i) + strconv.Itoa(id)
		}
		client.miners = append(client.miners, i)
		client.minerIPAddress[i] = theip
	}
}

func generateServerIPAddress(id int, servnum int) []string {
	res := []string{}
	for i:=0; i<servnum; i++ {
		var theip string
		if id<10 {
			theip = ipprefix + strconv.Itoa(i) + "0" + strconv.Itoa(id)
		} else {
			theip = ipprefix + strconv.Itoa(i) + strconv.Itoa(id)
		}
		res = append(res, theip)
	}
	//fmt.Println("client",id,"will sends tx to", res)
	return res
}

func (client *Client) Run() {
	go client.sendloop()

	rand.Seed(time.Now().UTC().UnixNano()+int64(client.id))
	//var hval [32]byte
	for i:=0; i<10000; i++ {
		rannum := rand.Uint64()
		ok, newtx := datastruc.MintNewTransaction(rannum, client.nodePubkeystr, client.nodePrvKey)
		if ok {
			client.BroadcastMintedTransaction(newtx, client.id, client.miners)
		}
		//val := rand.Intn(10) + 2
		val := 1
		time.Sleep(time.Millisecond*time.Duration(val))
	}
	fmt.Println("client", client.id, "stops")
}

func (client *Client) sendloop() {
	conns := make(map[int]net.Conn)
	for i, destip := range client.minerIPAddress {
		conn, err := net.Dial("tcp", destip)
		if err != nil {
			fmt.Printf("connect failed, err : %v\n", err.Error())
			return
		}
		conns[i] = conn
	}
	for {
		select {
		case datatosend := <-client.sendtxCh:
			data := append(datastruc.CommandToBytes(datatosend.MsgType), datatosend.Msg...)
			l := len(data)
			magicNum := make([]byte, 4)
			binary.BigEndian.PutUint32(magicNum, 0x123456)
			lenNum := make([]byte, 2)
			binary.BigEndian.PutUint16(lenNum, uint16(l))
			packetBuf := bytes.NewBuffer(magicNum)
			packetBuf.Write(lenNum)
			packetBuf.Write(data)
			for _, conn := range conns {
				_, err := conn.Write(packetBuf.Bytes())
				if err != nil {
					fmt.Printf("write failed , err : %v\n", err)
					break
				}
			}
		}
	}
}

func (client *Client) BroadcastMintedTransaction(newTransaction datastruc.Transaction, id int, dest []int) {
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(newTransaction)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	datatosend := datastruc.Datatosend{dest, "mintedtx", content}
	client.sendtxCh <- datatosend
}

func commandToBytes(command string) []byte {
	//command -> byte
	var bytees [commandLength]byte
	for i, c := range command {
		bytees[i] = byte(c)
	}
	return bytees[:]
}

func sendData(data []byte, addr string, id int) {
	conn, err := net.Dial(protocol, addr)
	if err != nil {
		fmt.Println("client", id, ":", addr, "is not available")
		//fmt.Printf("%s is not available\n", addr)
	} else {
		defer conn.Close()

		_, err = conn.Write(data)
		if err!=nil {
			fmt.Println("send error")
			log.Panic(err)
		}
	}
}