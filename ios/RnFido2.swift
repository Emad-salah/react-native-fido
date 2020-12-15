import Foundation
import WebAuthnKit
import UIKit

struct Log: TextOutputStream {

    func write(_ string: String) {
        let fm = FileManager.default
        let log = fm.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("fido2-log.txt")
        if let handle = try? FileHandle(forWritingTo: log) {
            handle.seekToEndOfFile()
            handle.write(string.data(using: .utf8)!)
            handle.closeFile()
        } else {
            try? string.data(using: .utf8)?.write(to: log)
        }
    }
}

var logger = Log()

@objc(RNFido2)
class RNFido2: NSObject {
    var nfcSessionStatus = false
    var accessorySessionStatus = false
    var webAuthnClient: WebAuthnClient?
    private var rpId: NSDictionary?
    private var user: NSDictionary?
    private var nfcSessionStateObservation: NSKeyValueObservation?
    private var accessorySessionStateObservation: NSKeyValueObservation?

    @objc
    func initialize(
      _ origin: String, 
      resolver resolve: @escaping RCTPromiseResolveBlock,
      rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
      let app = UIApplication.shared.delegate as! AppDelegate
      let rootViewController = app?.window??.rootViewController
      if (rootViewController != nil) {
        let userConsentUI = UserConsentUI(viewController: rootViewController)
        let authenticator = InternalAuthenticator(ui: userConsentUI)

        self.webAuthnClient = WebAuthnClient(
          origin: origin,
          authenticator: authenticator
        )
      }
    }

    @objc
    func setRpId(
      _ id: String,
      name: String,
      icon: String,
      resolver resolve: @escaping RCTPromiseResolveBlock,
      rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
      if (id == nil) {
        reject("RpIdError", "ID not specified")
      }

      if (name == nil) {
        reject("RpIdError", "Name not specified")
      }

      self.rpId = [
        "id": id,
        "name": name,
        "icon": icon
      ]

      resolve("RpId has been set successfully!")
    }

    @objc
    func setUser(
      _ identifier: String,
      name: String,
      displayName: String,
      icon: String,
      resolver resolve: @escaping RCTPromiseResolveBlock,
      rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
      if (identifier == nil) {
        reject("RpIdError", "ID not specified")
      }

      if (name == nil) {
        reject("RpIdError", "Name not specified")
      }

      if (displayName == nil) {
        reject("RpIdError", "Display name not specified")
      }

      self.user = [
        "id": identifier,
        "name": name,
        "displayName": name,
        "icon": icon
      ]

      resolve("User has been set successfully!")
    }

    func getEnumValue(value: String) -> Any {
      if (value == "direct") {
        return .direct
      }

      if (value == "indirect") {
        return .indirect
      }

      if (value == "none") {
        return .none
      }

      if (value == "required") {
        return .required
      }

      if (value == "preferred") {
        return .preferred
      }

      if (value == "discouraged") {
        return .discouraged
      }

      return nil
    }
    
    @objc
    func registerFido2(
        _ challenge: String,
        attestation: String? = "direct",
        timeoutNumber: NSNumber? = NSNumber(int: 60),
        requireResidentKey: Bool? = false,
        userVerification: String? = "discouraged",
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) -> Void {
        if (webAuthnClient == nil) {
          reject("RegisterError", "Please initialize the lib before performing any operation")
          return
        }

        if (challenge == nil) {
          reject("RegisterError", "Please specify a challenge")
          return
        }

        if (user == nil) {
          reject("RegisterError", "Please use .setUser before calling the register function")
          return
        }

        if (rpId == nil) {
          reject("RegisterError", "Please use .setRpId before calling the register function")
          return
        }

        let timeout = timeoutNumber?.integerValue ?? 60
        let options = PublicKeyCredentialCreationOptions()

        options.challenge = Bytes.fromHex(challenge) // must be Array<UInt8>
        options.user.id = Bytes.fromString(user.userId) // must be Array<UInt8>
        options.user.name = user.name
        options.user.displayName = user.displayName
        options.user.icon = user.icon  // Optional
        options.rp.id = rpId.id
        options.rp.name = rpId.name
        options.rp.icon = rpId.icon // Optional
        options.attestation = getEnumValue(attestation)



        options.addPubKeyCredParam(alg: .es256)
        options.authenticatorSelection = AuthenticatorSelectionCriteria(
            requireResidentKey: requireResidentKey, // this flag is ignored by InternalAuthenticator
            userVerification: getEnumValue(attestation) // (choose from .required, .preferred, .discouraged)
        )

        if (attestation != nil) {
          reject("RegisterError", "Please specify a challenge")
          return
        }

        self.webAuthnClient.create(options).then { credential in
          // send parameters to your server

          // credential.id
          // credential.rawId
          // credential.response.attestationObject
          // credential.response.clientDataJSON

          let response: NSDictionary = [
            "id": credential.id,
            "rawId": credential.rawId,
            "attestationObject": credential.response.attestationObject,
            "clientDataJSON": credential.response.clientDataJSON
          ]

          resolve(response)
        }.catch { error in
          // error handling
          reject("WebAuthnCreateError", error)
        }
    }
}
 
