package com.pvryan.easycryptsample;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import com.pvryan.easycrypt.ECryptResultListener;
import com.pvryan.easycrypt.asymmetric.ECryptAsymmetric;
import com.pvryan.easycrypt.asymmetric.ECryptRSAKeyPairListener;
import com.pvryan.easycrypt.hash.ECryptHash;
import com.pvryan.easycrypt.hash.ECryptHashAlgorithms;
import com.pvryan.easycrypt.symmetric.ECryptSymmetric;

import org.jetbrains.annotations.NotNull;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class StringFragment extends Fragment implements ECryptResultListener {

    private ECryptSymmetric eCryptSymmetric = new ECryptSymmetric();
    private ECryptAsymmetric eCryptAsymmetric = new ECryptAsymmetric();
    private RSAPrivateKey privateKey;
    private ECryptHash eCryptHash = new ECryptHash();

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
                        break;
                    case R.id.rbAsymmetricS:
                        edPassword.setVisibility(View.GONE);
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
                        eCryptHash.calculate(edInput.getText().toString(),
                                ECryptHashAlgorithms.SHA_512, StringFragment.this);
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
                                eCryptSymmetric.encrypt(edInput.getText().toString(),
                                        edPassword.getText().toString(), StringFragment.this);
                                break;
                            case R.id.rbAsymmetricS:
                                eCryptAsymmetric.generateKeyPair(new ECryptRSAKeyPairListener() {
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
                                    public void onSuccess(@NotNull KeyPair keyPair) {
                                        privateKey = (RSAPrivateKey) keyPair.getPrivate();
                                        eCryptAsymmetric.encrypt(edInput.getText().toString(),
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
                        ProgressBar progressBar = new ProgressBar(buttonDecrypt.getContext());
                        progressBar.setIndeterminate(true);
                        switch (rgType.getCheckedRadioButtonId()) {
                            case R.id.rbSymmetricS:
                                eCryptSymmetric.decrypt(edInput.getText().toString(),
                                        edPassword.getText().toString(), StringFragment.this);
                                break;
                            case R.id.rbAsymmetricS:
                                eCryptAsymmetric.decrypt(edInput.getText().toString(),
                                        privateKey, StringFragment.this);
                                break;
                        }
                    }
                }
        );
    }

    @Override
    public <T> void onSuccess(final T result) {
        getActivity().runOnUiThread(new Runnable() {
            @Override
            public void run() {
                tvResult.setText((String) result);
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

    @Override
    public void onProgress(int newBytes, long bytesProcessed) {
        // Not required for strings
    }
}
