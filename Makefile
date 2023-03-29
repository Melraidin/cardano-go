GOGEN = go generate
GOBUILD = go build
GOTEST = go test

## TODO: check if git and autotools are available to generate dependencies for libsodium
./libsodium/_c_libsodium_built/libsodium.a:
	$(GOGEN) ./libsodium/...
	touch $@

csigner: ./libsodium/_c_libsodium_built/libsodium.a
	CGO_ENABLED=1 \
	CGO_CFLAGS=-I$(CURDIR)/libsodium/_c_libsodium_built/include \
	CGO_LDFLAGS=-L$(CURDIR)/libsodium/_c_libsodium_built \
	$(GOBUILD) -o ./cli/build/$@ cli/$@/main.go

cwallet:
	$(GOBUILD) -o ./cli/build/$@ cli/$@/main.go

install:
	@cp ./cli/build/cwallet /usr/bin/

test:
	$(GOTEST) ./...

testcov:
	$(GOTEST) ./... -coverprofile coverage.out

opencov:
	go tool cover -html coverage.out
