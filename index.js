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

const Fido2 = {
  init: async origin => {
    if (!origin) {
      throw new Error("Please specify an origin URL");
    }

    if (Platform.OS === "ios") {
      await RNFido2.initialize(origin);
      return "Initialized";
    }

    return "Initialized";
  },
  setRpId: async ({ id, name, icon }) => {
    const rpEntity = await RNFido2.setRpId(id, name, icon);
    return rpEntity;
  },
  setAppId: async ({ url }) => {
    const appId = await RNFido2.setAppId(url);
    return appId;
  },
  setUser: async ({ id, username, displayName, icon }) => {
    const user = await Platform.select({
      ios: () => RNFido2.setUser(username, username, username, icon),
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
    const parsedSignedData = {
      id: toWebsafeBase64(signedData.id),
      rawId: toWebsafeBase64(signedData.rawId),
      clientDataJSON: toWebsafeBase64(signedData.clientDataJSON),
      attestationObject: toWebsafeBase64(signedData.attestationObject)
    };
    return parsedSignedData;
  },
  signChallenge: async ({
    keyHandles,
    challenge,
    appId = "",
    options = { timeout: 60 }
  }) => {
    const parsedOptions = {
      timeout: 60,
      ...(options || {})
    };
    if (appId) {
      await Fido2.setAppId({ url: appId });
    }
    const signedData = await RNFido2.signFido2(
      keyHandles.map(keyHandle => toNormalBase64(keyHandle)),
      toNormalBase64(challenge),
      parsedOptions
    );

    const parsedSignedData = {
      id: toWebsafeBase64(signedData.id),
      rawId: toWebsafeBase64(signedData.rawId),
      signature: toWebsafeBase64(signedData.signature),
      attestationObject: toWebsafeBase64(signedData.attestationObject),
      clientDataJSON: toWebsafeBase64(signedData.clientDataJSON),
      userHandle: signedData.userHandle
        ? toWebsafeBase64(signedData.userHandle)
        : undefined
    };
    return parsedSignedData;
  }
};

export default Fido2;
