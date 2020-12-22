package client

import (
	"../datastruc"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	b64 "encoding/base32"
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
	nodeaccountstr string // a base64 string

	sendvolume int
	starttime time.Time
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
	client.starttime = time.Now()
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
	hv := sha256.Sum256([]byte(client.nodePubkeystr))
	client.nodeaccountstr = b64.StdEncoding.EncodeToString(hv[:])
	//fmt.Println("client", client.id, "privatekey is", client.nodePrvKey)
	fmt.Println("client", client.id, "pubkey string is", client.nodePubkeystr)
	return client
}

func (client *Client) Run() {
	fmt.Println("client", client.id, "starts")
	go client.sendloop()

	time.Sleep(time.Second * 4)
	val := rand.Intn(400)
	time.Sleep(time.Millisecond*time.Duration(val))

	rand.Seed(time.Now().UTC().UnixNano()+int64(client.id))
	for i:=0; i<40000; i++ {
		rannum := rand.Uint64()
		ok, newtx := datastruc.MintNewTransaction(rannum, client.nodeaccountstr, client.nodePrvKey)
		//fmt.Println("analysing tx:")
		//fmt.Println("tx kind", newtx.Kind, "length:", len(newtx.Kind))
		//fmt.Println("tx timestamp", newtx.Timestamp, "length:", unsafe.Sizeof(newtx.Timestamp))
		//fmt.Println("tx source", newtx.Source, "length:", len(newtx.Source))
		//fmt.Println("tx recipient", newtx.Recipient, "length:", len(newtx.Recipient))
		//fmt.Println("tx value", newtx.Value, "length:", unsafe.Sizeof(newtx.Value))
		//fmt.Println("tx sig", newtx.Sig, "length:", unsafe.Sizeof(newtx.Sig))
		if ok {
			client.BroadcastMintedTransaction(newtx, client.id, client.miners)
			if i%1000==0 {
				//fmt.Println("tx", i, "timestamp is", newtx.Timestamp)
				elaps := time.Since(client.starttime).Seconds()
				fmt.Println("client", client.id, "sends", i, "txs in", elaps, "s")
			}
		}
		if i%5==0 {
			time.Sleep(time.Millisecond*50) // 25ms seems good, 30ms also good for test.
		}
		//val := rand.Intn(2) + 1
		//val := 10000
		//time.Sleep(time.Millisecond*10)
	}
	fmt.Println("client", client.id, "stops, time:", time.Since(client.starttime).Seconds(), "s")
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
	trytime := 0
	for {

		destip := client.minerIPAddress[destid]
		conn, err := net.Dial("tcp", destip)
		if err != nil {
			fmt.Println("connect failed, will retry later\n", err.Error())
			if trytime<=3 {
				fmt.Println("will re connect soon, time:", time.Since(client.starttime).Seconds(), "s")
				t := rand.Intn(1000)
				time.Sleep(time.Millisecond * time.Duration(t))
				trytime += 1
			} else {
				fmt.Println("try time reaches the upper bound, stops")
				time.Sleep(time.Second * 40)
			}
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
					client.sendvolume += len(packetBuf.Bytes())
					_, err := conn.Write(packetBuf.Bytes())
					//datalen := len(packetBuf.Bytes())
					//blank := make([]byte, 1000-datalen)
					//packetBuf.Write(blank)
					if err != nil {
						fmt.Println("write failed, time:", time.Since(client.starttime).Seconds(), "s")
						fmt.Printf("err: %v", err)
						t := rand.Intn(100)
						fmt.Println("will re connect soon, time:", time.Since(client.starttime).Seconds(), "s")
						time.Sleep(time.Millisecond * time.Duration(t))
						break innerloop
					} else {
						//fmt.Println("client", client.id, "total bytes sent is ", client.sendvolume)
					}
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
	//fmt.Println("the tx has size:", len(content))
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