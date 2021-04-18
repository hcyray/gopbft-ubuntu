sudo su
cd /home/ubuntu/go/src/gopbft-ubuntu
export GO111MODULE=off
export GOPATH=/home/ubuntu/go/src/gopbft-ubuntu
git pull
go run main.go

