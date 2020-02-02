package com.rnfido;

import android.app.Activity;
import android.content.Intent;
import android.content.IntentSender;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.Iterator;

import com.facebook.react.bridge.ActivityEventListener;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.BaseActivityEventListener;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReadableArray;

import com.facebook.react.bridge.WritableMap;
import com.google.android.gms.fido.fido2.Fido2ApiClient;
import com.google.android.gms.fido.fido2.Fido2PendingIntent;
import com.google.android.gms.fido.fido2.api.common.AuthenticationExtensions;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse;
import com.google.android.gms.fido.fido2.api.common.FidoAppIdExtension;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialDescriptor;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialType;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialUserEntity;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity;
import com.google.android.gms.fido.Fido;
import com.google.android.gms.fido.u2f.api.common.ResponseData;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;

public class RNFido2Module extends ReactContextBaseJavaModule {

    private final ReactApplicationContext reactContext;
    private static final int REQUEST_CODE_REGISTER = 0;
    private static final int REQUEST_CODE_SIGN = 1;
    private static final String E_SIGN_CANCELLED = "E_SIGN_CANCELLED";
    private static final String TAG = "RNFido2";

    private Promise mSignPromise;

    private final ActivityEventListener mActivityEventListener = new BaseActivityEventListener() {
        @Override
        public void onActivityResult(Activity activity, int requestCode, int resultCode, Intent intent) {
            if (requestCode == REQUEST_CODE_SIGN) {
                if (mSignPromise != null) {
                    if (resultCode == Activity.RESULT_CANCELED) {
                        mSignPromise.reject(E_SIGN_CANCELLED, "Sign was cancelled");
                    } else if (resultCode == Activity.RESULT_OK) {
                        Log.i(TAG, "Received response from Security Key");
                        AuthenticatorAssertionResponse signedData =
                                AuthenticatorAssertionResponse.deserializeFromBytes(
                                        intent.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA));
                        WritableMap response = Arguments.createMap();
                        response.putString("clientData", Base64.encodeToString(signedData.getClientDataJSON(), Base64.DEFAULT));
                        response.putString("authenticatorData", Base64.encodeToString(signedData.getAuthenticatorData(), Base64.DEFAULT));
                        response.putString("keyHandle", Base64.encodeToString(signedData.getKeyHandle(), Base64.DEFAULT));
                        response.putString("signature", Base64.encodeToString(signedData.getSignature(), Base64.DEFAULT));
                        mSignPromise.resolve(response);
                    }
                }
                mSignPromise = null;
            }
        }
    };

    public RNFido2Module(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;

        reactContext.addActivityEventListener(mActivityEventListener);
    }

    @Override
    @NonNull
    public String getName() {
        return "RNFido2";
    }

    @ReactMethod
    public void signFido2(ReadableArray keyHandles, String challenge, String appId, String rpId, Promise promise) {
        if (appId.isEmpty()) {
            promise.reject("appId", "Please specify an App ID");
            return;
        }

        if (rpId.isEmpty()) {
            promise.reject("rpId", "Please specify an RP ID");
            return;
        }

        mSignPromise = promise;

        // All the option parameters should come from the Relying Party / server
        ArrayList<PublicKeyCredentialDescriptor> allowedKeys = new ArrayList<PublicKeyCredentialDescriptor>();

        for (int i = 0; i < keyHandles.size(); i++) {
            String keyHandle = keyHandles.getString(i);
            byte[] keyHandleByte = Base64.decode(keyHandle, Base64.DEFAULT);
            allowedKeys.add(
                    new PublicKeyCredentialDescriptor(
                            PublicKeyCredentialType.PUBLIC_KEY.toString(),
                            keyHandleByte,
                            null
                    )
            );
        }

        PublicKeyCredentialRequestOptions options = new PublicKeyCredentialRequestOptions.Builder()
            .setRpId(rpId.length() > 0 ? rpId : appId)
            .setAuthenticationExtensions(
                    new AuthenticationExtensions.Builder()
                        .setFido2Extension(new FidoAppIdExtension(appId))
                        .build()
            )
            .setAllowList(allowedKeys)
            .setChallenge(Base64.decode(challenge, Base64.DEFAULT))
            .build();

        Fido2ApiClient fido2ApiClient = Fido.getFido2ApiClient(this.reactContext);
        Task<Fido2PendingIntent> fido2PendingIntentTask = fido2ApiClient.getSignIntent(options);
        final Activity activity = this.reactContext.getCurrentActivity();
        fido2PendingIntentTask.addOnSuccessListener(
            new OnSuccessListener<Fido2PendingIntent>() {
                @Override
                public void onSuccess(Fido2PendingIntent fido2PendingIntent) {
                    if (fido2PendingIntent.hasPendingIntent()) {
                        try {
                            // Start a FIDO2 registration request.
                            fido2PendingIntent.launchPendingIntent(activity, REQUEST_CODE_SIGN);
                        } catch (IntentSender.SendIntentException e) {
                            Log.e(TAG, "Error launching pending intent for sign request", e);
                        }
                    }
                }
            }
        );
    }

}
