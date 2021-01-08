package main

import (
	"./client"
	"./server"
	"./datastruc"
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// Get preferred outbound ip of this machine
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func ReadAllIps(fn string) []string {
	fmt.Println("read all ips")

	file, err := os.Open(fn)
	if err!=nil {
		log.Panic("error")
	}
	res := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// fmt.Println(scanner.Text())
		res = append(res, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return res
}

func DetermineId(allips []string, localip string) int {
	for i, ip := range allips {
		if ip==localip {
			return i
		}
	}
	return -1
}

func RecordClientKeys(clk *client.ClienKeys) {
	file, err := os.OpenFile("clientkeys", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
	if err!=nil {
		fmt.Println("create clientkey file error")
	}
	enc := gob.NewEncoder(file)
	err = enc.Encode(clk.GetSerialize())
	if err!=nil {
		fmt.Println("write config to file error")
	}
}

func ReadClientKeys(fn string)  client.ClienKeys {
	ck := client.ClienKeys{}

	ck.GetDeserializeFromFile(fn)

	return ck
}

func main() {

	var tmp string
	tmp = "main"

	if tmp=="clientkey" {
		// ***************************************generate client keys and save
		ck := client.ClienKeys{}
		ck.Clienprivks = make(map[int]string)
		ck.Clientpubkstrs = make(map[int]string)
		for i:=0; i<20000; i++ {
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
			if err != nil {
				log.Fatalln(err)
			}
			ck.Clienprivks[i] = datastruc.EncodePrivate(privateKey)
			pubkey := &privateKey.PublicKey
			ck.Clientpubkstrs[i] = datastruc.EncodePublic(pubkey)
		}
		RecordClientKeys(&ck)
		// ***************************************generate client keys and save
	} else if tmp=="main" {
		fmt.Println("add account_hash_generation_time, backup")
		fmt.Println("Get the cluster IPs from", os.Args[1])
		fmt.Println("Get client keys from", os.Args[2])
		localip := GetOutboundIP().String()
		fmt.Println("local ip: ", localip)
		allips := ReadAllIps(os.Args[1])
		fmt.Println("all ips: ")
		for _, x := range allips {
			fmt.Println(x)
		}
		localid := DetermineId(allips, localip)
		fmt.Println("local id is", localid, "\n")

		clientnumber := 32
		instanceoneachserver := 1
		initialserver := 9
		lateserver := 0 // mechanism1
		totalserver := initialserver + lateserver
		// read client pubkeys
		ck := ReadClientKeys(os.Args[2])
		if localid<initialserver {
			// invoke two server
			for i:=0; i<instanceoneachserver; i++ {
				instanceid := i+instanceoneachserver*localid
				theserver := server.CreateServer(instanceid, localip, ck.Clientpubkstrs, allips[0:initialserver], instanceoneachserver)
				go theserver.Start()
				fmt.Println("server", instanceid, "starts")
			}
		} else if localid>=initialserver && localid<totalserver {
			for i:=0; i<instanceoneachserver; i++ {
				instanceid := i+instanceoneachserver*localid
				theserver := server.CreateLateServer(instanceid, localip, ck.Clientpubkstrs, allips[0:initialserver], instanceoneachserver)
				starttime := 90+10*(localid-initialserver)
				go theserver.LateStart(ck.Clientpubkstrs, starttime) // new nodes join serially
				fmt.Println("server", instanceid, "starts, it is a late server, will start at", starttime, "s")
			}
		} else {
			//invoke clients
			for i:=0; i<clientnumber; i++ {
				privatekey := datastruc.DecodePrivate(ck.Clienprivks[i])
				theclient := client.CreateClient(i, totalserver*instanceoneachserver, privatekey, allips[0:totalserver], instanceoneachserver)
				go theclient.Run()
				fmt.Println("the ", i, "client starts")
			}
		}
		time.Sleep(time.Second * 175)
	} else {
		fmt.Printf("tmp is ", tmp)
	}
	fmt.Println("main thread completes")
}