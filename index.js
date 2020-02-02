import { NativeModules } from "react-native";

const { RNFido2 } = NativeModules;

const Fido2 = {
	signChallenge: async ({ keyHandles, challenge, appId = "", rpId = "" }) => {
		const signedData = await RNFido2.signFido2(
			keyHandles,
			challenge,
			appId,
			rpId
		);
		return signedData;
	}
};

export default Fido2;
