#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(RNFido2, NSObject)
  RCT_EXTERN_METHOD(initialize:(NSString *)type resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

  RCT_EXTERN_METHOD(setRpId:(NSString *)id name:(NSString *)name icon:(NSString *)icon resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

  RCT_EXTERN_METHOD(setUser:(NSString *)id name:(NSString *)name displayName:(NSString *)displayName icon:(NSString *)icon resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

  RCT_EXTERN_METHOD(registerFido2:(NSString *)challenge attestation:(NSString *)attestation timeoutNumber:(nonnull NSNumber *)timeoutNumber requireResidentKey:(BOOL *)requireResidentKey userVerification:(NSString *)userVerification resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

  RCT_EXTERN_METHOD(signFido2:(NSString *)challenge allowedCredentials:(NSArray *)allowedCredentials userVerification:(NSString *)userVerification resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
@end
