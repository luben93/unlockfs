//go:build darwin

package platform

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation -framework Security -framework ApplicationServices
#include <stdlib.h>
int ul_prompt(const char *reason);
int ul_key_get(unsigned char *out32);
int ul_key_add(const unsigned char *key32);
int ul_screen_locked(void);
*/
import "C"

import (
	"crypto/rand"
	"errors"
	"unsafe"
)

func systemPrompt(reason string) bool {
	c := C.CString(reason)
	defer C.free(unsafe.Pointer(c))
	return C.ul_prompt(c) == 1
}

func systemKey() ([]byte, error) {
	k := make([]byte, 32)
	if C.ul_key_get((*C.uchar)(unsafe.Pointer(&k[0]))) == 0 {
		return k, nil
	}
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if C.ul_key_add((*C.uchar)(unsafe.Pointer(&k[0]))) != 0 {
		return nil, errors.New("cannot store key in keychain")
	}
	return k, nil
}

func screenLocked() bool { return C.ul_screen_locked() == 1 }
