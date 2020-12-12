#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(RNYubikit, NSObject)
  RCT_EXTERN_METHOD(init:(NSString *)type resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

  RCT_EXTERN_METHOD(setRpId:(NSString *)id name:(NSString *)name icon:(NSString *)icon resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

  RCT_EXTERN_METHOD(setUser:(NSString *)id name:(NSString *)name displayName:(NSString *)displayName icon:(NSString *)icon resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

  RCT_EXTERN_METHOD(registerFido2:(NSString *)challenge attestation:(NSString *)attestation timeout:(NSNumber *)timeout requireResidentKey:(BOOL *)requireResidentKey userVerification:(NSString *)userVerification resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
@end
