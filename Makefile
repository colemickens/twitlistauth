all: build

install-systemd-service:
	sudo cp twitlistauth.service /etc/systemd/system/twitlistauth.service
	sudo systemctl daemon-reload;
	sudo systemctl stop twitlistauth.service; sudo systemctl start twitlistauth.service && sudo systemctl enable twitlistauth.service;

build:
	go build -o twitlistauth main.go

run: build
	./twitlistauth
