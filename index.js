import { NativeModules, Platform } from "react-native";

const { RNFido2 } = NativeModules;

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
  setRpId: async ({ id, url, icon }) => {
    const rpEntity = await RNFido2.setRpId(id, url, icon);
    return rpEntity;
  },
  setAppId: async ({ url }) => {
    const appId = await RNFido2.setAppId(url);
    return appId;
  },
  setUser: async ({ username, icon }) => {
    const user = await RNFido2.setUser(username, icon);
    return user;
  },
  registerKey: async ({
    keyHandles = [],
    challenge,
    appId,
    publicKeyAlgorithms = [-7],
    options = {
      timeout: 60,
      requireResidentKey: true,
      attestationPreference: "direct",
      userVerification: "discouraged"
    }
  }) => {
    if (Platform.OS === "android") {
      if (appId) {
        Fido2.setAppId({ url: appId });
      }
      const signedData = await RNFido2.registerFido2(
        keyHandles,
        challenge,
        publicKeyAlgorithms,
        {
          timeout: 60,
          requireResidentKey: true,
          attestationPreference: "direct",
          ...options
        }
      );
      return signedData;
    }

    if (Platform.OS === "ios") {
      const signedData = await RNFido2.registerFido2(
        challenge,
        options.attestationPreference,
        options.timeout,
        options.requireResidentKey,
        options.userVerification
      );
      return signedData;
    }
  },
  signChallenge: async ({ keyHandles, challenge, appId = "" }) => {
    if (appId) {
      Fido2.setAppId({ url: appId });
    }
    const signedData = await RNFido2.signFido2(keyHandles, challenge);
    return signedData;
  }
};

export default Fido2;
