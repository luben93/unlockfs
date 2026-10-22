module github.com/unlockfs/unlockfs

go 1.22

require github.com/winfsp/cgofuse v1.5.0

// FUSE-T compatible fork of cgofuse (same module path, links against libfuse-t on macOS)
replace github.com/winfsp/cgofuse => github.com/macos-fuse-t/cgofuse v0.0.0-20220916074051-3e7192100b68
