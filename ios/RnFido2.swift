import Foundation
import RNWebAuthnKit
import UIKit
import PromiseKit

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
      _ hostOrigin: String?,
      resolver resolve: @escaping RCTPromiseResolveBlock,
      rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
      DispatchQueue.main.async {
        let presentedViewController = RCTPresentedViewController();

        guard let currentViewController = presentedViewController else {
          print("[Fido2 Swift] Error: Unable to retrieve the current view controller", to: &logger)
          reject("WebAuthnInitializeError", "Unable to retrieve the current view controller", nil)
          return
        }

        guard let origin = hostOrigin else {
          print("[Fido2 Swift] Error: Please specify an origin URL", to: &logger)
          reject("WebAuthnInitializeError", "Invalid origin URL specified", nil)
          return
        }

        let userConsentUI = UserConsentUI(viewController: currentViewController)
        let authenticator = InternalAuthenticator(ui: userConsentUI)

        self.webAuthnClient = WebAuthnClient(
          origin: origin,
          authenticator: authenticator
        )

        print("[Fido2 Swift] Initialized view controller successfully!", to: &logger)

        resolve(true)
      }
    }

    @objc
    static func requiresMainQueueSetup() -> Bool {
        return true
    }

    @objc
    func setRpId(
      _ id: String,
      name: String,
      icon: String,
      resolver resolve: @escaping RCTPromiseResolveBlock,
      rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
      if id.isEmpty {
        print("[Fido2 Swift] RpIdError: ID not specified", to: &logger)
        reject("RpIdError", "ID not specified", nil)
        return
      }

      if name.isEmpty {
        print("[Fido2 Swift] RpIdError: Name not specified", to: &logger)
        reject("RpIdError", "Name not specified", nil)
        return
      }

      rpId = [
        "id": id,
        "name": name,
        "icon": icon
      ]

      print("[Fido2 Swift] RpId has been set successfully!", to: &logger)
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
      if identifier.isEmpty {
        print("[Fido2 Swift] RpIdError: ID not specified", to: &logger)
        reject("RpIdError", "ID not specified", nil)
        return
      }

      if name.isEmpty {
        print("[Fido2 Swift] RpIdError: Name not specified", to: &logger)
        reject("RpIdError", "Name not specified", nil)
        return
      }

      if displayName.isEmpty {
        print("[Fido2 Swift] RpIdError: Display name not specified", to: &logger)
        reject("RpIdError", "Display name not specified", nil)
        return
      }

      user = [
        "id": identifier,
        "name": name,
        "displayName": displayName,
        "icon": icon
      ]

      print("[Fido2 Swift] User has been set successfully!", to: &logger)
      resolve("User has been set successfully!")
    }

    func getEnumValue(value: String) -> Any {
      if (value == "direct") {
        return AttestationConveyancePreference.direct
      }

      if (value == "indirect") {
        return AttestationConveyancePreference.indirect
      }

      if (value == "none") {
        return AttestationConveyancePreference.none
      }

      if (value == "required") {
        return UserVerificationRequirement.required
      }

      if (value == "preferred") {
        return UserVerificationRequirement.preferred
      }

      if (value == "discouraged") {
        return UserVerificationRequirement.discouraged
      }

      return AttestationConveyancePreference.none
    }
    
    func base64ToByte( _ base64UrlText: String) -> [UInt8] {
        let base64Text = base64UrlText
          .replacingOccurrences(of: "-", with: "+")
          .replacingOccurrences(of: "_", with: "/")
        
        let base64Data: Data = Data(base64Encoded: base64Text)!

        let byteBase64 = [UInt8](base64Data)
        
        return byteBase64
    }

    func bufferToBase64(_ bufferData: [UInt8]?) -> String {
        guard let bufferBytes = bufferData else {
            return ""
        }
      let data = NSData(bytes: bufferBytes, length: bufferBytes.count)
      let base64String = data.base64EncodedString(options: [])

      return base64String
    }

    func stringToBase64(_ stringData: String) -> String {
      let utf8str = stringData.data(using: .utf8)
      let base64Encoded = utf8str?.base64EncodedString(options: Data.Base64EncodingOptions(rawValue: 0)) ?? ""
      return base64Encoded
    }
    
    @objc
    func registerFido2(
        _ base64URLChallenge: String,
        attestation: String = "direct",
        timeoutNumber: NSNumber? = NSNumber(value: 60),
        requireResidentKey: Bool,
        userVerification: String = "discouraged",
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) -> Void {
        if base64URLChallenge.isEmpty {
          print("[Fido2 Swift] Register Error: Please specify a challenge", to: &logger)
          reject("RegisterError", "Please specify a challenge", nil)
          return
        }

        guard let webAuthn = self.webAuthnClient else {
          print("[Fido2 Swift] Error: Please initialize the lib before performing any operation", to: &logger)
          reject("RegisterError", "Please initialize the lib before performing any operation", nil)
          return
        }

        guard let requestUser = user else {
          print("[Fido2 Swift] Error: Please use .setUser before calling the register function", to: &logger)
          reject("RegisterError", "Please use .setUser before calling the register function", nil)
          return
        }

        guard let requestRpId = rpId else {
          print("[Fido2 Swift] Error: Please use .setRpId before calling the register function", to: &logger)
          reject("RegisterError", "Please use .setRpId before calling the register function", nil)
          return
        }

        guard let userId = requestUser["id"] as? String else {
          print("[Fido2 Swift] Error: Please use .setUser before calling the register function", to: &logger)
          reject("RegisterError", "Please use .setUser before calling the register function", nil)
          return
        }

        let challenge = self.base64ToByte(base64URLChallenge)

//        let timeout = timeoutNumber?.intValue ?? 60
        var options = PublicKeyCredentialCreationOptions()

        options.challenge = challenge // must be Array<UInt8>
        options.user.id = Bytes.fromString(userId) // must be Array<UInt8>
        options.user.name = requestUser["name"] as? String ?? ""
        options.user.displayName = requestUser["displayName"] as? String ?? ""
        options.user.icon = requestUser["icon"] as? String ?? ""  // Optional
        options.rp.id = requestRpId["id"] as? String ?? ""
        options.rp.name = requestRpId["name"] as? String ?? ""
        options.rp.icon = requestRpId["icon"] as? String ?? "" // Optional
        options.attestation = getEnumValue(value: attestation) as! AttestationConveyancePreference

        options.addPubKeyCredParam(alg: .es256)
        options.authenticatorSelection = AuthenticatorSelectionCriteria(
            requireResidentKey: requireResidentKey, // this flag is ignored by InternalAuthenticator
            userVerification: UserVerificationRequirement.discouraged // (choose from .required, .preferred, .discouraged)
        )
        
        DispatchQueue.main.async {
          firstly {
              webAuthn.create(options)
          }.done { (credential: WebAuthnClient.CreateResponse) in
            // send parameters to your server

            // credential.id
            // credential.rawId
            // credential.response.attestationObject
            // credential.response.clientDataJSON

            let response: NSDictionary = [
              "id": credential.id,
              "rawId": self.bufferToBase64(credential.rawId),
              "attestationObject": self.bufferToBase64(credential.response.attestationObject),
              "clientDataJSON": self.stringToBase64(credential.response.clientDataJSON)
            ]

            resolve(response)
          }.catch { error in
              // error handling
              let errorType: String? = "WebAuthnCreateError"
              let errorCast: Error? = error
              print("[Fido2 Swift] WebAuthN.create Error: \(error.localizedDescription)", to: &logger)
              reject(errorType, "Failed to create a new WebAuthn credential", errorCast)
          }
        }
    }

    @objc
    func signFido2(
        _ base64URLChallenge: String,
        allowedCredentials: NSMutableArray,
        userVerification: String = "discouraged",
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) -> Void {
        if base64URLChallenge.isEmpty {
          print("[Fido2 Swift] Error: Please specify a challenge", to: &logger)
          reject("SignError", "Please specify a challenge", nil)
          return
        }

        guard let webAuthn = self.webAuthnClient else {
          print("[Fido2 Swift] Error: Please initialize the lib before performing any operation", to: &logger)
          reject("SignError", "Please initialize the lib before performing any operation", nil)
          return
        }

        guard let requestRpId = rpId else {
          print("[Fido2 Swift] Error: Please use .setRpId before calling the sign function", to: &logger)
          reject("SignError", "Please use .setRpId before calling the sign function", nil)
          return
        }

        let challenge = base64ToByte(base64URLChallenge)

//        let timeout = timeoutNumber?.intValue ?? 60
        var options = PublicKeyCredentialRequestOptions()

        options.challenge = challenge // must be Array<UInt8>
        options.rpId = requestRpId["id"] as? String ?? ""

        options.userVerification = UserVerificationRequirement.discouraged
        allowedCredentials.map { (credentialId: Any) in
            if let credentialIdString = credentialId as? String {
                options.addAllowCredential(
                    credentialId: base64ToByte(credentialIdString),
                    transports: [.internal_]
                )
            }
        }
        
        DispatchQueue.main.async {
          firstly {
              webAuthn.get(options)
          }.done { (credential: WebAuthnClient.GetResponse) in
            let response: NSDictionary = [
              "id": credential.id,
              "rawId": self.bufferToBase64(credential.rawId),
              "authenticatorData": self.bufferToBase64(credential.response.authenticatorData),
              "clientDataJSON": self.stringToBase64(credential.response.clientDataJSON),
              "signature": self.bufferToBase64(credential.response.signature),
              "userHandle": self.bufferToBase64(credential.response.userHandle)
            ]

            resolve(response)
          }.catch { error in
              // error handling
              let errorType: String? = "WebAuthnCreateError"
              let errorCast: Error? = error
              print("[Fido2 Swift] WebAuthN.create Error: \(error.localizedDescription)", to: &logger)
              reject(errorType, "Failed to create a new WebAuthn credential", errorCast)
          }
        }
    }
}