FUSE_INC ?= /usr/local/include/fuse
FUSE_LIB ?= /usr/local/lib
SWIFTFLAGS = -swift-version 5 -O -I Sources/cfuse -Xcc -I$(FUSE_INC) -L$(FUSE_LIB) -lfuse-t -Xlinker -rpath -Xlinker $(FUSE_LIB)
# SIGN_ID="Apple Development: you@example.com (TEAMID)" gives the binary a stable identity (keychain won't re-prompt after rebuilds)
SIGN_ID ?= -

.PHONY: all test clean install
all: unlockfs

unlockfs: Sources/unlockfs.swift
	swiftc $(SWIFTFLAGS) $< -o $@
	codesign -f -s "$(SIGN_ID)" $@

# test-only build: UNLOCKFS_AUTH=test replaces the prompt with a control file. Never install this binary.
unlockfs-test: Sources/unlockfs.swift
	swiftc $(SWIFTFLAGS) -D UNLOCKFS_TESTING $< -o $@

test: unlockfs-test
	./test/run.sh

install: unlockfs
	./contrib/install-launchd.sh

clean:
	rm -rf unlockfs unlockfs-test test/.run
