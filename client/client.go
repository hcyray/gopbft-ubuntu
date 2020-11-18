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
	"os"
	"time"
)

type ClienKeys struct {
	Clienprivks map[int]string
	Clientpubkstrs map[int]string
}

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

type TxPack struct {
	Txs []datastruc.Transaction
}

func (clk *ClienKeys) GetSerialize() []byte {
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(clk)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	return content
}

func (clk *ClienKeys) GetDeserializeFromFile(fn string) {

	var conten []byte
	file, err := os.Open(fn)
	if err!=nil {
		fmt.Println("open clientkey file error")
	}
	dec := gob.NewDecoder(file)
	err = dec.Decode(&conten)
	if err!=nil {
		fmt.Println("read clientkey file error")
	}
	var buff bytes.Buffer
	buff.Write(conten)
	gob.Register(elliptic.P256())
	decc := gob.NewDecoder(&buff)
	err = decc.Decode(clk)
	if err!=nil {
		fmt.Println("serialized client key decoding error")
	}
}

func CreateClient(id int, servernum int, privateKey *ecdsa.PrivateKey, allips []string) *Client {
	client := &Client{}
	client.id = id
	client.miners = make([]int, 0)
	client.minerIPAddress = make(map[int]string)
	for i:=0; i<servernum; i++ {
		client.miners = append(client.miners, i)
		order := i/2
		client.minerIPAddress[i] = allips[order] + ":4" + datastruc.GenerateTwoBitId(i) + datastruc.GenerateTwoBitId(id)
	}
	//client.generateServerOrderIp(servernum)
	fmt.Println("client ", id, "will send tx to the following servers", client.miners)
	fmt.Println("client ", id, "will send tx to the following address", client.minerIPAddress)
	client.sendtxCh = make(chan datastruc.Datatosend)

	publicKey := &privateKey.PublicKey
	client.nodePrvKey = privateKey
	client.nodePubKey = publicKey
	client.nodePrvkeystr = datastruc.EncodePrivate(privateKey)
	client.nodePubkeystr = datastruc.EncodePublic(publicKey)
	//fmt.Println("client", client.id, "privatekey is", client.nodePrvKey)
	fmt.Println("client", client.id, "pubkey string is", client.nodePubkeystr)
	return client
}

func (client *Client) Run() {
	fmt.Println("client", client.id, "starts")
	go client.sendloop()

	rand.Seed(time.Now().UTC().UnixNano()+int64(client.id))
	//var hval [32]byte
	for i:=0; i<10000000; i++ {
		txbatch := make([]datastruc.Transaction, 0)
		coun := 0
		for {
			rannum := rand.Uint64()
			ok, newtx := datastruc.MintNewTransaction(rannum, client.nodePubkeystr, client.nodePrvKey)
			if ok {
				txbatch = append(txbatch, newtx)
			}
			coun += 1
			if coun>=10 {
				break
			}
		}
		client.BroadcastMintedTransactionBatch(txbatch, client.id, client.miners)

		//val := rand.Intn(6000)
		val := 60 + rand.Intn(60)
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

func (client *Client) BroadcastMintedTransactionBatch(txbatch []datastruc.Transaction, id int, dest []int) {
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(txbatch)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	datatosend := datastruc.Datatosend{dest, "mintedtxbatch", content}
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