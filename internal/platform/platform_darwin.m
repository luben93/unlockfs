#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#import <ApplicationServices/ApplicationServices.h>

int ul_prompt(const char *reason) {
  @autoreleasepool {
    LAContext *c = [LAContext new];
    NSError *e = nil;
    if (![c canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&e]) return 0;
    dispatch_semaphore_t s = dispatch_semaphore_create(0);
    __block int ok = 0;
    [c evaluatePolicy:LAPolicyDeviceOwnerAuthentication
      localizedReason:[NSString stringWithUTF8String:reason]
                reply:^(BOOL success, NSError *err) { ok = success ? 1 : 0; dispatch_semaphore_signal(s); }];
    dispatch_semaphore_wait(s, DISPATCH_TIME_FOREVER);
    return ok;
  }
}

static NSDictionary *ul_query(void) {
  return @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: @"unlockfs", (__bridge id)kSecAttrAccount: @"store-key" };
}

int ul_key_get(unsigned char *out32) {
  @autoreleasepool {
    NSMutableDictionary *q = [ul_query() mutableCopy];
    q[(__bridge id)kSecReturnData] = @YES;
    CFTypeRef res = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &res) != errSecSuccess) return 1;
    NSData *d = (__bridge_transfer NSData *)res;
    if (d.length != 32) return 1;
    memcpy(out32, d.bytes, 32);
    return 0;
  }
}

int ul_key_add(const unsigned char *key32) {
  @autoreleasepool {
    NSMutableDictionary *q = [ul_query() mutableCopy];
    q[(__bridge id)kSecValueData] = [NSData dataWithBytes:key32 length:32];
    return SecItemAdd((__bridge CFDictionaryRef)q, NULL) == errSecSuccess ? 0 : 1;
  }
}

int ul_screen_locked(void) {
  CFDictionaryRef d = CGSessionCopyCurrentDictionary();
  if (!d) return 0;
  CFBooleanRef v = CFDictionaryGetValue(d, CFSTR("CGSSessionScreenIsLocked"));
  int r = (v && CFBooleanGetValue(v)) ? 1 : 0;
  CFRelease(d);
  return r;
}
