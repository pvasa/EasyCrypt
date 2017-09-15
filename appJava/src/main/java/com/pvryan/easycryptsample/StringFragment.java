package com.pvryan.easycryptsample;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.os.Environment;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import com.pvryan.easycrypt.ECKeys;
import com.pvryan.easycrypt.ECResultListener;
import com.pvryan.easycrypt.asymmetric.ECAsymmetric;
import com.pvryan.easycrypt.asymmetric.ECRSAKeyPairListener;
import com.pvryan.easycrypt.asymmetric.ECVerifiedListener;
import com.pvryan.easycrypt.hash.ECHash;
import com.pvryan.easycrypt.hash.ECHashAlgorithms;
import com.pvryan.easycrypt.symmetric.ECSymmetric;

import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class StringFragment extends Fragment implements ECResultListener {

    private ECSymmetric eCSymmetric = new ECSymmetric();
    private ECAsymmetric eCAsymmetric = new ECAsymmetric();
    private ECHash eCHash = new ECHash();
    private ECKeys eCKeys = new ECKeys();
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    private LinearLayout llSignVerifyS;
    private EditText edInput;
    private EditText edPassword;
    private TextView tvResult;
    private RadioGroup rgType;
    private ProgressBar pBar;

    private ClipboardManager clipboard;

    public StringFragment() {
    }

    /**
     * Returns a new instance of this fragment for the given section
     * number.
     */
    public static StringFragment newInstance() {
        return new StringFragment();
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_string, container, false);
    }

    @Override
    public void onViewCreated(View view, @Nullable Bundle savedInstanceState) {

        clipboard = (ClipboardManager) getActivity().getSystemService(Context.CLIPBOARD_SERVICE);

        llSignVerifyS = (LinearLayout) view.findViewById(R.id.llSignVerifyS);
        edInput = (EditText) view.findViewById(R.id.edInputS);
        edPassword = (EditText) view.findViewById(R.id.edPasswordS);
        tvResult = (TextView) view.findViewById(R.id.tvResultS);
        tvResult.setOnLongClickListener(new View.OnLongClickListener() {
            @Override
            public boolean onLongClick(View v) {
                ClipData data = ClipData.newPlainText("result", ((TextView) v).getText());
                clipboard.setPrimaryClip(data);
                Toast.makeText(getActivity(),
                        "Result copied to clipboard", Toast.LENGTH_LONG).show();
                return true;
            }
        });

        pBar = (ProgressBar) view.findViewById(R.id.progressBarS);
        pBar.setIndeterminate(true);

        rgType = (RadioGroup) view.findViewById(R.id.rgTypeS);

        rgType.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                switch (checkedId) {
                    case R.id.rbSymmetricS:
                        edPassword.setVisibility(View.VISIBLE);
                        llSignVerifyS.setVisibility(View.GONE);
                        break;
                    case R.id.rbAsymmetricS:
                        edPassword.setVisibility(View.GONE);
                        llSignVerifyS.setVisibility(View.VISIBLE);
                        break;
                }
            }
        });

        view.findViewById(R.id.buttonHashS).setOnClickListener(
                new View.OnClickListener() {
                    @Override
                    public void onClick(final View buttonHash) {
                        pBar.setVisibility(View.VISIBLE);
                        pBar.setIndeterminate(true);
                        eCHash.calculate(edInput.getText().toString(),
                                ECHashAlgorithms.SHA_512, StringFragment.this);
                    }
                }
        );

        view.findViewById(R.id.buttonEncryptS).setOnClickListener(
                new View.OnClickListener() {
                    @Override
                    public void onClick(final View buttonEncrypt) {
                        pBar.setVisibility(View.VISIBLE);
                        pBar.setIndeterminate(true);
                        switch (rgType.getCheckedRadioButtonId()) {
                            case R.id.rbSymmetricS:
                                eCSymmetric.encrypt(edInput.getText().toString(),
                                        edPassword.getText().toString(), StringFragment.this);
                                break;
                            case R.id.rbAsymmetricS:
                                eCKeys.genRSAKeyPair(new ECRSAKeyPairListener() {
                                    @Override
                                    public void onFailure(@NotNull final String message, @NotNull Exception e) {
                                        e.printStackTrace();
                                        getActivity().runOnUiThread(new Runnable() {
                                            @Override
                                            public void run() {
                                                pBar.setVisibility(View.INVISIBLE);
                                                Toast.makeText(getActivity(), message,
                                                        Toast.LENGTH_LONG).show();
                                            }
                                        });
                                    }

                                    @Override
                                    public void onGenerated(@NotNull KeyPair keyPair) {
                                        privateKey = (RSAPrivateKey) keyPair.getPrivate();
                                        eCAsymmetric.encrypt(edInput.getText().toString(),
                                                (RSAPublicKey) keyPair.getPublic(), StringFragment.this);
                                    }
                                });
                                break;
                        }
                    }
                }
        );

        view.findViewById(R.id.buttonDecryptS).setOnClickListener(
                new View.OnClickListener() {
                    @Override
                    public void onClick(final View buttonDecrypt) {
                        pBar.setVisibility(View.VISIBLE);
                        pBar.setIndeterminate(true);
                        switch (rgType.getCheckedRadioButtonId()) {
                            case R.id.rbSymmetricS:
                                eCSymmetric.decrypt(edInput.getText().toString(),
                                        edPassword.getText().toString(), StringFragment.this);
                                break;
                            case R.id.rbAsymmetricS:
                                eCAsymmetric.decrypt(edInput.getText().toString(),
                                        privateKey, StringFragment.this);
                                break;
                        }
                    }
                }
        );

        view.findViewById(R.id.buttonSignS).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                pBar.setVisibility(View.VISIBLE);
                pBar.setIndeterminate(true);

                final File sigFile = new File(Environment.getExternalStorageDirectory(),
                        "ECryptSample/sample.sig");
                if (sigFile.exists()) sigFile.delete();

                eCKeys.genRSAKeyPair(new ECRSAKeyPairListener() {
                    @Override
                    public void onGenerated(@NotNull KeyPair keyPair) {
                        publicKey = (RSAPublicKey) keyPair.getPublic();
                        eCAsymmetric.sign(edInput.getText(),
                                (RSAPrivateKey) keyPair.getPrivate(),
                                StringFragment.this, sigFile);
                    }

                    @Override
                    public void onFailure(@NotNull String message, @NotNull Exception e) {
                        e.printStackTrace();
                        getActivity().runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                Toast.makeText(getActivity(),
                                        "Failed to generate RSA key pair. Try again.",
                                        Toast.LENGTH_LONG).show();
                            }
                        });
                    }
                });
            }
        });

        view.findViewById(R.id.buttonVerifyS).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                pBar.setVisibility(View.VISIBLE);
                pBar.setIndeterminate(true);

                eCAsymmetric.verify(edInput.getText(), publicKey,
                        new File(Environment.getExternalStorageDirectory(),
                                "ECryptSample/sample.sig"), new ECVerifiedListener() {
                            @Override
                            public void onProgress(int newBytes, long bytesProcessed) {
                            }

                            @Override
                            public void onSuccess(final boolean verified) {
                                getActivity().runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        if (verified) tvResult.setText(R.string.msg_valid);
                                        else tvResult.setText(R.string.msg_invalid);
                                        pBar.setVisibility(View.INVISIBLE);
                                    }
                                });
                            }

                            @Override
                            public void onFailure(@NotNull final String message, @NotNull Exception e) {
                                e.printStackTrace();
                                getActivity().runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        Toast.makeText(getActivity(), message, Toast.LENGTH_LONG).show();
                                        pBar.setVisibility(View.INVISIBLE);
                                    }
                                });
                            }
                        });
            }
        });
    }

    @Override
    public <T> void onSuccess(final T result) {
        getActivity().runOnUiThread(new Runnable() {
            @Override
            public void run() {
                pBar.setVisibility(View.INVISIBLE);
                if (result instanceof File)
                    tvResult.setText(getResources().getString(
                            R.string.success_result_to_file,
                            ((File) result).getAbsolutePath()));
                else if (result instanceof String)
                    tvResult.setText((String) result);
                else tvResult.setText(R.string.result_undefined);
            }
        });
    }

    @Override
    public void onFailure(@NotNull final String message, @NotNull Exception e) {
        e.printStackTrace();
        getActivity().runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(getActivity(), message, Toast.LENGTH_LONG).show();
                pBar.setVisibility(View.INVISIBLE);
            }
        });
    }

    @Override
    public void onProgress(int newBytes, long bytesProcessed) {
        // Not required for strings
    }
}
