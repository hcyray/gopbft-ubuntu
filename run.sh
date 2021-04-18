sudo su
cd /home/ubuntu/go/src/gopbft-ubuntu
export GO111MODULE=off
export GOPATH=/home/ubuntu/go/src/gopbft-ubuntu
ulimit -n 4096
git pull
go run main.go

