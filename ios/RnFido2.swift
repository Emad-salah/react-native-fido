import Foundation
import WebAuthnKit
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

extension String {
  func UTF8toBase64() -> String {
    let data = self.data(using:String.Encoding.utf8)
    return data?.base64EncodedString(options: []) ?? ""
  }

  func Base64toUTF8() -> String {
    let data = NSData.init(base64Encoded: self, options: []) ?? NSData()
    return String(data: data as Data, encoding: String.Encoding.utf8) ?? ""
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
        "displayName": name,
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
          print("[Fido2 Swift] Error: Please specify a challenge", to: &logger)
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

        let challengeBase64 = base64URLChallenge
          .replacingOccurrences(of: "-", with: "+")
          .replacingOccurrences(of: "_", with: "/")
        
        let challengeData: Data = Data(base64Encoded: challengeBase64)!

        let challenge = [UInt8](challengeData)

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
            userVerification: UserVerificationRequirement.preferred // (choose from .required, .preferred, .discouraged)
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
              "rawId": credential.rawId.toBase64() ?? "",
              "attestationObject": credential.response.attestationObject.toBase64() ?? "",
              "clientDataJSON": credential.response.clientDataJSON.UTF8toBase64()
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
 
