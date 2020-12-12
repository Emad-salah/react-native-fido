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
    func init(
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

    @objc
    private func signNFCU2F(
        session: YKFNFCSession,
        challenge: String,
        appId: String,
        keyHandles: [String],
        callback: @escaping (String?, NSDictionary?) -> ()
    ) {
        let semaphore = DispatchSemaphore(value: 0)
        var signedChallenge = false
        DispatchQueue.global().async {
            for keyHandle in keyHandles {
                guard !signedChallenge else {
                    break
                }
                
                // The challenge and appId are received from the authentication server.
                guard let signRequest = YKFKeyU2FSignRequest(challenge: challenge, keyHandle: keyHandle, appId: appId) else {
                    continue
                }
                
                guard #available(iOS 13.0, *) else {
                    callback("NFCUnsupported", nil)
                    _ = self.stopNFCSession()
                    self.nfcSessionStateObservation = nil
                    break
                }
                
                guard session.iso7816SessionState == .open else {
                    let error = "NFCSessionClosed"
                    callback(error, nil)
                    _ = self.stopNFCSession()
                    self.nfcSessionStateObservation = nil
                    break
                }

                YubiKitManager.shared.nfcSession.u2fService!.execute(signRequest) { [weak self] (response, error) in
                    guard error == nil else {
                        // Handle the error
                        print("[iOS Swift] U2F Error: \(error?.localizedDescription)")
                        semaphore.signal()
                        return
                    }
                    // The response should not be nil at this point. Send back the response to the authentication server.
                    if (debugMode) {
                      print("[iOS Swift] NFC U2F Sign Data:", response, to: &logger)
                    }
                    let signData: NSDictionary = [
                        "clientData": response?.clientData.data(using: .utf8)?.base64EncodedString(options: .endLineWithLineFeed) ?? "",
                        "keyHandle": response?.keyHandle ?? "",
                        "signatureData": response?.signature.base64EncodedString(options: .endLineWithLineFeed) ?? ""
                    ]
                    signedChallenge = true
                    semaphore.signal()
                    _ = self?.stopNFCSession()
                    self?.nfcSessionStateObservation = nil
                    callback(nil, signData)
                }
                semaphore.wait()
            }

            if !signedChallenge {
                _ = self.stopNFCSession()
                self.nfcSessionStateObservation = nil
                print("[iOS Swift] Security Key error occurred or user has dismissed prompt")
                callback("InvalidSecurityKey", nil)
            }
        }
    }

    @objc
    private func signAccessoryU2F(
        session: YKFAccessorySession,
        challenge: String,
        appId: String,
        keyHandles: [String],
        callback: @escaping (String?, NSDictionary?) -> ()
    ) {
        let semaphore = DispatchSemaphore(value: 0)
        var signedChallenge = false
        DispatchQueue.global().async {
            for keyHandle in keyHandles {
                guard !signedChallenge else {
                    break
                }
                
                // The challenge and appId are received from the authentication server.
                guard let signRequest = YKFKeyU2FSignRequest(challenge: challenge, keyHandle: keyHandle, appId: appId) else {
                    continue
                }
                
                guard session.sessionState == .open else {
                    let error = "NFCSessionClosed"
                    callback(error, nil)
                    _ = self.stopAccessorySession()
                    self.accessorySessionStateObservation = nil
                    break
                }

                YubiKitManager.shared.accessorySession.u2fService!.execute(signRequest) { [weak self] (response, error) in
                    guard error == nil else {
                        // Handle the error
                        print("[iOS Swift] U2F Error: \(error?.localizedDescription)")
                        semaphore.signal()
                        return
                    }
                    // The response should not be nil at this point. Send back the response to the authentication server.
                    if (debugMode) {
                      print("[iOS Swift] Accessory U2F Sign Data:", response, to: &logger)
                    }
                    let signData: NSDictionary = [
                        "clientData": response?.clientData.data(using: .utf8)?.base64EncodedString(options: .endLineWithLineFeed) ?? "",
                        "keyHandle": response?.keyHandle ?? "",
                        "signatureData": response?.signature.base64EncodedString(options: .endLineWithLineFeed) ?? ""
                    ]
                    signedChallenge = true
                    semaphore.signal()
                    _ = self?.stopAccessorySession()
                    self?.accessorySessionStateObservation = nil
                    callback(nil, signData)
                }
                semaphore.wait()
            }

            if !signedChallenge {
                _ = self.stopAccessorySession()
                self.accessorySessionStateObservation = nil
                callback("InvalidSecurityKey", nil)
            }
        }
    }

    @objc
    func executeSignU2F(
        _ type: String,
        keyHandles: [String],
        challenge: String,
        appId: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        if type == "nfc" {
            guard #available(iOS 13.0, *), YubiKitDeviceCapabilities.supportsISO7816NFCTags else {
                reject("NFCUnsupported", "Your device doesn't support NFC", nil)
                return
            }

            let nfcSession = YubiKitManager.shared.nfcSession as! YKFNFCSession

            // The ISO7816 session is started only when required since it's blocking the application UI with the NFC system action sheet.
            let sessionStarted = nfcSession.iso7816SessionState == .open ? true : self.initNFCSession()
            var responseSent = false
            
            guard sessionStarted else {
                reject("NFCUnsupported", "NFC is not supported on this device", nil)
                return
            }
            
            // Execute the request after the key(tag) is connected.
            nfcSessionStateObservation = nfcSession.observe(\.iso7816SessionState, changeHandler: { [weak self] session, change in
                if session.iso7816SessionState == .open {
                    self?.signNFCU2F(session: session, challenge: challenge, appId: appId, keyHandles: keyHandles) { error, response in
                        guard error == nil else {
                            responseSent = true
                            reject(error, "An error has occurred", nil)
                            return
                        }

                        responseSent = true
                        resolve(response)
                    }
                }

                if session.iso7816SessionState == .closed {
                    guard let error = session.iso7816SessionError else {
                            // session was closed without an error
                                    return
                    }
                    let errorCode = (error as NSError).code;
                    if errorCode == NFCReaderError.readerSessionInvalidationErrorUserCanceled.rawValue {
                        // user pressed cancel button 
                        reject("PromptCancelled", "User has cancelled the prompt", nil)
                        return
                    }
                }
            })
        } else {
            guard YubiKitDeviceCapabilities.supportsMFIAccessoryKey else {
                reject("KeyUnsupported", "Your device doesn't support FIDO Keys", nil)
                return
            }

            let accessorySession = YubiKitManager.shared.accessorySession as! YKFAccessorySession

            // The ISO7816 session is started only when required since it's blocking the application UI with the NFC system action sheet.
            let sessionStarted = accessorySession.sessionState == .open ? true : self.initAccessoryession()
            
            guard sessionStarted else {
                reject("KeyUnsupported", "Your device doesn't support FIDO Keys", nil)
                return
            }
            
            // Execute the request after the key(tag) is connected.
            accessorySessionStateObservation = accessorySession.observe(\.sessionState, changeHandler: { [weak self] session, change in
                if session.sessionState == .open {
                    self?.signAccessoryU2F(session: session, challenge: challenge, appId: appId, keyHandles: keyHandles) { error, response in
                        guard error != nil else {
                            reject(error, "An error has occurred", nil)
                            return
                        }

                        resolve(response)
                    }
                }
            })
        }
    }
}
 
