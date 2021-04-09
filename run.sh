sudo su
cd /home/ubuntu/go/src/gopbft-ubuntu
git pull
export GO111MODULE=off
export GOPATH=/home/ubuntu/go/src/gopbft-ubuntu
go run main.go

