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
	sendtxtooneCh []chan datastruc.Datatosend

	nodePubKey *ecdsa.PublicKey
	nodePrvKey *ecdsa.PrivateKey
	nodePubkeystr string
	nodePrvkeystr string
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

func CreateClient(id int, servernum int, privateKey *ecdsa.PrivateKey, allips []string, inseach int) *Client {
	client := &Client{}
	client.id = id
	client.miners = make([]int, 0)
	client.minerIPAddress = make(map[int]string)
	total := servernum * inseach
	for i:=0; i<total; i++ {
		client.miners = append(client.miners, i)
		order := i/inseach
		client.minerIPAddress[i] = allips[order] + ":4" + datastruc.GenerateTwoBitId(i) + "1"
	}
	//client.generateServerOrderIp(servernum)
	fmt.Println("client ", id, "will send tx to the following servers", client.miners)
	fmt.Println("client ", id, "will send tx to the following address", client.minerIPAddress)
	client.sendtxCh = make(chan datastruc.Datatosend)
	client.sendtxtooneCh = make([]chan datastruc.Datatosend, total)
	for i:=0; i<total; i++ {
		client.sendtxtooneCh[i] = make(chan datastruc.Datatosend)
	}


	publicKey := &privateKey.PublicKey
	client.nodePrvKey = privateKey
	client.nodePubKey = publicKey
	client.nodePrvkeystr = datastruc.EncodePrivate(privateKey)
	client.nodePubkeystr = datastruc.EncodePublic(publicKey)
	//fmt.Println("client", client.id, "privatekey is", client.nodePrvKey)
	fmt.Println("client", client.id, "pubkey string is", client.nodePubkeystr)
	return client
}

//func (client *Client) generateServerOrderIp(servnum int) {
//	//id := client.id
//	for i:=0; i<servnum; i++ {
//		var theip string
//		//if id<10 {
//		//	theip = ipprefix + strconv.Itoa(i)
//		//} else {
//		//	theip = ipprefix + strconv.Itoa(i)
//		//}
//		theip = ipprefix + datastruc.GenerateTwoBitId(i) + "1"
//		client.miners = append(client.miners, i)
//		client.minerIPAddress[i] = theip
//	}
//}

//func generateServerIPAddress(id int, servnum int) []string {
//	res := []string{}
//	for i:=0; i<servnum; i++ {
//		var theip string
//		if id<10 {
//			theip = ipprefix + strconv.Itoa(i) + "0" + strconv.Itoa(id)
//		} else {
//			theip = ipprefix + strconv.Itoa(i) + strconv.Itoa(id)
//		}
//		res = append(res, theip)
//	}
//	//fmt.Println("client",id,"will sends tx to", res)
//	return res
//}

func (client *Client) Run() {
	fmt.Println("client", client.id, "starts")
	go client.sendloop()

	rand.Seed(time.Now().UTC().UnixNano()+int64(client.id))
	//var hval [32]byte
	startime := time.Now()
	for i:=0; i<10; i++ {
		rannum := rand.Uint64()
		ok, newtx := datastruc.MintNewTransaction(rannum, client.nodePubkeystr, client.nodePrvKey)
		if ok {
			client.BroadcastMintedTransaction(newtx, client.id, client.miners)
			if i%1==0 {
				//fmt.Println("tx", i, "timestamp is", newtx.Timestamp)
				elaps := time.Since(startime).Milliseconds()
				fmt.Println("client sends", i, "txs in", elaps, "ms")
			}
		}
		//val := rand.Intn(2) + 1
		//val := 10000
		//time.Sleep(time.Nanosecond*time.Duration(val))
	}
	fmt.Println("client", client.id, "stops")
}

func (client *Client) sendloop() {
	for i:=0; i<len(client.minerIPAddress); i++ {
		go client.sendtooneloop(i)
	}

	for {
		select {
		case datatosend := <-client.sendtxCh:
			for i:=0; i<len(client.sendtxtooneCh); i++ {
				client.sendtxtooneCh[i] <- datatosend
			}
		}
	}
}

func (client *Client) sendtooneloop(destid int) {
	for {

		destip := client.minerIPAddress[destid]
		conn, err := net.Dial("tcp", destip)
		if err != nil {
			fmt.Println("connect failed, err : %v , will retry later\n", err.Error())
			t := rand.Intn(100)
			fmt.Println("will re connect soon")
			time.Sleep(time.Millisecond * time.Duration(t))
		} else {
		innerloop:
			for {
				select {
				case datatosend := <-client.sendtxtooneCh[destid]:
					data := append(datastruc.CommandToBytes(datatosend.MsgType), datatosend.Msg...)
					l := len(data)
					magicNum := make([]byte, 4)
					binary.BigEndian.PutUint32(magicNum, 0x123456)
					lenNum := make([]byte, 2)
					binary.BigEndian.PutUint16(lenNum, uint16(l))
					packetBuf := bytes.NewBuffer(magicNum)
					packetBuf.Write(lenNum)
					packetBuf.Write(data)
					_, err := conn.Write(packetBuf.Bytes())
					//datalen := len(packetBuf.Bytes())
					//blank := make([]byte, 1000-datalen)
					//packetBuf.Write(blank)
					if err != nil {
						fmt.Printf("write failed , err : %v\n", err)
						t := rand.Intn(100)
						fmt.Println("will re connect soon")
						time.Sleep(time.Millisecond * time.Duration(t))
						break innerloop
					}
				}
			}
		}
	}
}

//func (client *Client) sendloop() {
//	conns := make(map[int]net.Conn)
//	for i, destip := range client.minerIPAddress {
//		conn, err := net.Dial("tcp", destip)
//		if err != nil {
//			log.Panic("connect failed, err : %v\n", err.Error())
//		}
//		conns[i] = conn
//	}
//	for {
//		select {
//		case datatosend := <-client.sendtxCh:
//			data := append(datastruc.CommandToBytes(datatosend.MsgType), datatosend.Msg...)
//			l := len(data)
//			magicNum := make([]byte, 4)
//			binary.BigEndian.PutUint32(magicNum, 0x123456)
//			lenNum := make([]byte, 2)
//			binary.BigEndian.PutUint16(lenNum, uint16(l))
//			packetBuf := bytes.NewBuffer(magicNum)
//			packetBuf.Write(lenNum)
//			packetBuf.Write(data)
//			datalen := len(packetBuf.Bytes())
//			blank := make([]byte, 800-datalen)
//			packetBuf.Write(blank)
//			for _, conn := range conns {
//				_, err := conn.Write(packetBuf.Bytes())
//
//				//fmt.Println("client send message length ", len(packetBuf.Bytes()))
//				if err != nil {
//					fmt.Printf("write failed , err : %v\n", err)
//					break
//				}
//			}
//		}
//	}
//}

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