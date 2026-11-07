PREFIX ?= /usr/local
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GO111MODULE := on

DAEMON := uservone-amneziawg
CLI := uservone-awg

all: $(DAEMON) $(CLI)

$(DAEMON): $(wildcard *.go) $(wildcard */*.go)
	go build -trimpath -o "$@" .

$(CLI): $(wildcard cmd/uservone-awg/*.go) $(wildcard profile/*.go)
	go build -trimpath -o "$@" ./cmd/uservone-awg

install: all
	install -v -d "$(DESTDIR)$(BINDIR)"
	install -v -m 0755 "$(DAEMON)" "$(DESTDIR)$(BINDIR)/$(DAEMON)"
	install -v -m 0755 "$(CLI)" "$(DESTDIR)$(BINDIR)/$(CLI)"
	ln -sf "$(DAEMON)" "$(DESTDIR)$(BINDIR)/amneziawg-go"

test:
	go test ./...

clean:
	rm -f "$(DAEMON)" "$(CLI)" "$(DAEMON).exe" "$(CLI).exe"

.PHONY: all clean test install
