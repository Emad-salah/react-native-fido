package com.rnfido;

import android.app.Activity;
import android.app.PendingIntent;
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
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.Promise;

import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.google.android.gms.fido.fido2.Fido2ApiClient;
import com.google.android.gms.fido.fido2.Fido2PendingIntent;
import com.google.android.gms.fido.fido2.api.common.Attachment;
import com.google.android.gms.fido.fido2.api.common.AttestationConveyancePreference;
import com.google.android.gms.fido.fido2.api.common.AuthenticationExtensions;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorSelectionCriteria;
import com.google.android.gms.fido.fido2.api.common.EC2Algorithm;
import com.google.android.gms.fido.fido2.api.common.FidoAppIdExtension;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialDescriptor;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialParameters;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialType;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialUserEntity;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity;
import com.google.android.gms.fido.Fido;
import com.google.android.gms.fido.fido2.api.common.TokenBinding;
import com.google.android.gms.fido.fido2.api.common.UserVerificationMethodExtension;
import com.google.android.gms.fido.u2f.api.common.ResponseData;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;

import org.json.JSONObject;

public class RNFido2Module extends ReactContextBaseJavaModule {

    private final ReactApplicationContext reactContext;
    private static final int REQUEST_CODE_REGISTER = 110;
    private static final int REQUEST_CODE_SIGN = 111;
    private static final String E_SIGN_CANCELLED = "E_SIGN_CANCELLED";
    private static final String E_REGISTER_CANCELLED = "E_REGISTER_CANCELLED";
    private static final String TAG = "RNFido2";

    private Promise mSignPromise;
    private Promise mRegisterPromise;
    private PublicKeyCredentialRpEntity rpEntity;
    private PublicKeyCredentialUserEntity currentUser;
    private String appIcon;
    private String rpId;
    private String appId;

    private final ActivityEventListener mActivityEventListener = new BaseActivityEventListener() {
        @Override
        public void onActivityResult(Activity activity, int requestCode, int resultCode, Intent intent) {
            super.onActivityResult(activity, requestCode, resultCode, intent);

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
                        response.putString("userHandle", Base64.encodeToString(signedData.getUserHandle(), Base64.DEFAULT));
                        mSignPromise.resolve(response);
                    }
                }
                mSignPromise = null;
            }

            if (requestCode == REQUEST_CODE_REGISTER) {
                Log.i(TAG, "Received pending response from Fido2 Activity");
                if (mRegisterPromise != null) {
                    Log.i(TAG, "Received confirmed response from Fido2 Activity");
                    if (resultCode == Activity.RESULT_CANCELED) {
                        mRegisterPromise.reject(E_REGISTER_CANCELLED, "Register was cancelled");
                    } else if (resultCode == Activity.RESULT_OK) {
                        if (intent.hasExtra(Fido.FIDO2_KEY_ERROR_EXTRA)) {
                            AuthenticatorErrorResponse response =
                                AuthenticatorErrorResponse.deserializeFromBytes(
                                    intent.getByteArrayExtra(Fido.FIDO2_KEY_ERROR_EXTRA));
                            Log.e(TAG, "FIDO2_KEY_ERROR_EXTRA Security Key");
                        }

                        if (intent.hasExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA)) {
                            Log.i(TAG, "Received response from Security Key: " + Base64.encode(intent.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA), Base64.DEFAULT));
                            AuthenticatorAttestationResponse signedData =
                                    AuthenticatorAttestationResponse.deserializeFromBytes(
                                        intent.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA));
                            WritableMap response = Arguments.createMap();
                            response.putString("clientData", Base64.encodeToString(signedData.getClientDataJSON(), Base64.DEFAULT));
                            response.putString("authenticatorData", Base64.encodeToString(signedData.getAttestationObject(), Base64.DEFAULT));
                            response.putString("keyHandle", Base64.encodeToString(signedData.getKeyHandle(), Base64.DEFAULT));
                            mRegisterPromise.resolve(response);
                        }
                    }
                } else {
                    Log.i(TAG, "Register promise is null");
                }
                mRegisterPromise = null;
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
    public void setAppIcon(String icon, Promise promise) {
        appIcon = icon;
        promise.resolve(icon);
    }

    @ReactMethod
    public void setRpId(String id, String url, String icon, Promise promise) {
        if (icon == null || icon.isEmpty()) {
            icon = appIcon;
        }
        rpId = id;
        rpEntity = new PublicKeyCredentialRpEntity(rpId, url, icon);
        promise.resolve(id);
    }

    @ReactMethod
    public void setAppId(String url, Promise promise) {
        appId = url;
        promise.resolve(appId);
    }

    @ReactMethod
    public void setUser(String username, String icon, Promise promise) {
        currentUser = new PublicKeyCredentialUserEntity(username.getBytes(), username, icon, username);
        promise.resolve(true);
    }

    @ReactMethod
    public void registerFido2(ReadableArray keyHandles, String challenge, ReadableArray params, Promise promise) {
        mRegisterPromise = promise;

        // All the option parameters should come from the Relying Party / server
        ArrayList<PublicKeyCredentialDescriptor> existingKeys = new ArrayList<>();

        for (int i = 0; i < keyHandles.size(); i++) {
            String keyHandle = keyHandles.getString(i);
            byte[] keyHandleByte = Base64.decode(keyHandle, Base64.DEFAULT);
            existingKeys.add(
                    new PublicKeyCredentialDescriptor(
                            PublicKeyCredentialType.PUBLIC_KEY.toString(),
                            keyHandleByte,
                            null
                    )
            );
        }

        ArrayList<PublicKeyCredentialParameters> parameters = new ArrayList<>();
        for (int i = 0; i < params.size(); i++) {
            ReadableMap param = params.getMap(i);
            String type = param.getString("type");
            Double alg = param.getDouble("alg");
            // TODO: this is a hack, use KEY_PARAMETERS_ALGORITHM = "alg"
            PublicKeyCredentialParameters parameter =
                    new PublicKeyCredentialParameters(type, alg);
            parameters.add(parameter);
        }

        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions.Builder()
            .setRp(rpEntity)
            .setUser(currentUser)
            .setAttestationConveyancePreference(
                    AttestationConveyancePreference.NONE
            )
            .setChallenge(Base64.decode(challenge, Base64.DEFAULT))
            .setParameters(parameters)
            .setTimeoutSeconds(60d)
            .build();

        Fido2ApiClient fido2ApiClient = Fido.getFido2ApiClient(this.reactContext);
        Task<PendingIntent> fido2PendingIntentTask = fido2ApiClient.getRegisterPendingIntent(options);
        final Activity activity = this.reactContext.getCurrentActivity();
        fido2PendingIntentTask.addOnSuccessListener(
            new OnSuccessListener<PendingIntent>() {
                @Override
                public void onSuccess(PendingIntent fido2PendingIntent) {
                    if (fido2PendingIntent != null) {
                        // Start a FIDO2 sign request.
                        try {
                            activity.startIntentSenderForResult(
                                    fido2PendingIntent.getIntentSender(), 
                                    REQUEST_CODE_REGISTER, 
                                    null, // fillInIntent,
                                    0, // flagsMask,
                                    0, // flagsValue,
                                    0  //extraFlags
                            );
                        } catch (IntentSender.SendIntentException e) {
                            Log.e(TAG, "SendIntentException: " + e);
                            e.printStackTrace();
                        }
                    }
                }
            }
        );

        fido2PendingIntentTask.addOnFailureListener(
            new OnFailureListener() {
                @Override
                public void onFailure(Exception e) {
                    // Fail
                    mRegisterPromise.reject("unknown", e.getLocalizedMessage());
                    mRegisterPromise = null;
                }
            }
        );
    }

    @ReactMethod
    public void signFido2(ReadableArray keyHandles, String challenge, Promise promise) {
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
            .setRpId(rpId)
            .setAuthenticationExtensions(
                    new AuthenticationExtensions.Builder()
                        .setFido2Extension(new FidoAppIdExtension(appId))
                        .build()
            )
            .setAllowList(allowedKeys)
            .setChallenge(Base64.decode(challenge, Base64.DEFAULT))
                .setTimeoutSeconds(60d)
            .build();

        Fido2ApiClient fido2ApiClient = Fido.getFido2ApiClient(this.reactContext);
        final Task<PendingIntent> fido2PendingIntentTask = fido2ApiClient.getSignPendingIntent(options);
        final Activity activity = this.reactContext.getCurrentActivity();
        fido2PendingIntentTask.addOnSuccessListener(
            new OnSuccessListener<PendingIntent>() {
                @Override
                public void onSuccess(PendingIntent fido2PendingIntent) {
                    if (fido2PendingIntent != null) {
                        // Start a FIDO2 sign request.
                        try {
                            activity.startIntentSenderForResult(fido2PendingIntent.getIntentSender(),
                                REQUEST_CODE_SIGN,
                                null, // fillInIntent,
                                0, // flagsMask,
                                0, // flagsValue,
                                0 //extraFlags
                            );
                        } catch (IntentSender.SendIntentException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        );

        fido2PendingIntentTask.addOnFailureListener(
            new OnFailureListener() {
                @Override
                public void onFailure(Exception e) {
                    // Fail
                    mSignPromise.reject("unknown", e.getMessage());
                }
            }
        );
    }

}
