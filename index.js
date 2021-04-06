import { NativeModules, Platform } from "react-native";

const { RNFido2 } = NativeModules;

const toWebsafeBase64 = (text = "") => {
  return text
    .replace(/\//g, "_")
    .replace(/\+/g, "-")
    .replace(/[=]/g, "")
    .replace(/\\n/g, "")
    .replace(/\n/g, "");
};

const toNormalBase64 = (text = "") => {
  let encoded = text
    .replace(/\-/g, "+")
    .replace(/\_/g, "/")
    .replace(/\\n/g, "")
    .replace(/\n/g, "");
  while (encoded.length % 4) {
    encoded += "=";
  }
  return encoded;
};

let appOrigin = null;

let initialized = false;

const Fido2 = {
  init: async origin => {
    if (!origin) {
      throw new Error("Please specify an origin URL");
    }

    if (!appOrigin) {
      appOrigin = origin;
    }

    return "Initialized";
  },
  setRpId: async ({ id, name, icon }) => {
    const rpEntity = await RNFido2.setRpId(id, name, icon);
    return rpEntity;
  },
  setAppId: async ({ url }) => {
    if (Platform.OS === "ios") {
      return appId;
    }

    const appId = await RNFido2.setAppId(url);
    return appId;
  },
  setUser: async ({ id, username, displayName, icon }) => {
    const user = await Platform.select({
      ios: () => RNFido2.setUser(username, username, displayName, icon),
      android: () =>
        RNFido2.setUser(id, username, icon, displayName || username)
    })();
    return user;
  },
  registerKey: async ({
    keyHandles = [],
    challenge,
    appId,
    publicKeyAlgorithms = [{ type: "public-key", alg: -7 }],
    options = {
      timeout: 60,
      requireResidentKey: true,
      authenticatorType: "any",
      attestationPreference: "direct",
      userVerification: "discouraged"
    }
  }) => {
    try {
      if (!initialized && Platform.OS === "ios") {
        await RNFido2.initialize(appOrigin);
      }
      const parsedOptions = {
        timeout: 60,
        requireResidentKey: true,
        attestationPreference: "direct",
        userVerification: "discouraged",
        authenticatorType: "any",
        ...(options || {})
      };
      if (appId) {
        await Fido2.setAppId({ url: appId });
      }
      const signedData = await Platform.select({
        ios: () =>
          RNFido2.registerFido2(
            toNormalBase64(challenge),
            parsedOptions.attestationPreference,
            parsedOptions.timeout,
            parsedOptions.requireResidentKey,
            parsedOptions.userVerification
          ),
        android: () =>
          RNFido2.registerFido2(
            keyHandles.map(keyHandle => toNormalBase64(keyHandle)),
            toNormalBase64(challenge),
            publicKeyAlgorithms,
            parsedOptions
          )
      })();
      console.log(signedData);
      const parsedSignedData = {
        id: toWebsafeBase64(signedData.id),
        rawId: toWebsafeBase64(signedData.rawId),
        clientDataJSON: toWebsafeBase64(signedData.clientDataJSON),
        attestationObject: toWebsafeBase64(signedData.attestationObject)
      };
      return parsedSignedData;
    } catch (err) {
      console.error(err);
      throw err;
    }
  },
  signChallenge: async ({
    keyHandles,
    challenge,
    appId = "",
    options = { timeout: 60, appId: true }
  }) => {
    const parsedOptions = {
      timeout: 60,
      appId: false,
      ...(options || {})
    };
    try {
      if (!initialized && Platform.OS === "ios") {
        await RNFido2.initialize(appOrigin);
      }
      if (appId && parsedOptions.appId) {
        await Fido2.setAppId({ url: appId });
      }

      if (!parsedOptions.appId) {
        await Fido2.setAppId({ url: null });
      }

      const signedData = await Platform.select({
        android: () =>
          RNFido2.signFido2(
            keyHandles.map(keyHandle => toNormalBase64(keyHandle)),
            toNormalBase64(challenge),
            parsedOptions
          ),
        ios: () =>
          RNFido2.signFido2(
            toNormalBase64(challenge),
            keyHandles.map(keyHandle => toNormalBase64(keyHandle)),
            "discouraged"
          )
      })();

      const parsedSignedData = {
        id: toWebsafeBase64(signedData.id),
        rawId: toWebsafeBase64(signedData.rawId),
        signature: toWebsafeBase64(signedData.signature),
        attestationObject: toWebsafeBase64(signedData.attestationObject),
        authenticatorData: toWebsafeBase64(signedData.authenticatorData),
        clientDataJSON: toWebsafeBase64(signedData.clientDataJSON),
        userHandle: signedData.userHandle
          ? toWebsafeBase64(signedData.userHandle)
          : undefined,
        extensions: {
          appid: parsedOptions.appId
        }
      };
      console.log("parsedSignedData:", parsedSignedData);
      return parsedSignedData;
    } catch (err) {
      const sanitizedErrorMessage = err?.message?.toLowerCase() ?? "";
      if (
        (sanitizedErrorMessage.includes("0x6a80") ||
          sanitizedErrorMessage.includes("SW_WRONG_DATA")) &&
        !parsedOptions.appId
      ) {
        console.warn(
          "SW_WRONG_DATA (0x6a80): Retrying assertion request with AppID extension..."
        );
        const signedData = await Fido2.signChallenge({
          keyHandles,
          challenge,
          appId,
          options: { ...parsedOptions, appId: true }
        });
        console.log(
          "Assertion request signed with AppID extension successfully!"
        );

        return signedData;
      }

      throw err;
    }
  }
};

export default Fido2;
