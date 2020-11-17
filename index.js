import { NativeModules } from "react-native";

const { RNFido2 } = NativeModules;

const Fido2 = {
	setRpId: async ({ id, url, icon }) => {
		const rpEntity = await RNFido2.setRpId(
			id,
			url,
			icon
		);
		return rpEntity;
	},
	setAppId: async ({ url }) => {
		const appId = await RNFido2.setAppId(
			url
		);
		return appId;
	},
	setUser: async ({ username, icon }) => {
		const user = await RNFido2.setUser(
			username,
			icon
		);
		return user;
	},
	registerKey: async ({ keyHandles = [], challenge, appId, publicKeyAlgorithms }) => {
		if (appId) {
			Fido2.setAppId({ url: appId });
		}
		console.log("Registering Key...", keyHandles, challenge)
		const signedData = await RNFido2.registerFido2(
			keyHandles,
			challenge,
			publicKeyAlgorithms
		);
		return signedData;
	},
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
