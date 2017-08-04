package com.pvryan.easycryptsample;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.NonNull;
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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class FileFragment extends Fragment implements ECryptResultListener {

    private final int RC_HASH = 2;
    private final int RC_ENCRYPT = 3;
    private final int RC_DECRYPT = 4;

    private ECryptSymmetric eCryptSymmetric = new ECryptSymmetric();
    private ECryptAsymmetric eCryptAsymmetric = new ECryptAsymmetric();
    private RSAPrivateKey privateKey;
    private ECryptHash eCryptHash = new ECryptHash();

    private EditText edPassword;
    private TextView tvResult;
    private RadioGroup rgType;
    private ProgressBar pBar;

    private ClipboardManager clipboard;

    public FileFragment() {
    }

    public static FileFragment newInstance() {
        return new FileFragment();
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_file, container, false);
    }

    @Override
    public void onViewCreated(View view, @Nullable Bundle savedInstanceState) {

        clipboard = (ClipboardManager) getActivity().getSystemService(Context.CLIPBOARD_SERVICE);

        edPassword = (EditText) view.findViewById(R.id.edPasswordF);
        tvResult = (TextView) view.findViewById(R.id.tvResultF);
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

        pBar = (ProgressBar) getActivity().findViewById(R.id.progressBarF);

        rgType = (RadioGroup) view.findViewById(R.id.rgTypeF);
        rgType.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                switch (checkedId) {
                    case R.id.rbSymmetricF:
                        edPassword.setVisibility(View.VISIBLE);
                        break;
                    case R.id.rbAsymmetricF:
                        edPassword.setVisibility(View.GONE);
                        break;
                }
            }
        });

        view.findViewById(R.id.buttonSelectHashF)
                .setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view1) {
                        selectFile(RC_HASH);
                    }
                });
        view.findViewById(R.id.buttonSelectEncryptF)
                .setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view1) {
                        selectFile(RC_ENCRYPT);
                    }
                });
        view.findViewById(R.id.buttonSelectDecryptF)
                .setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view1) {
                        selectFile(RC_DECRYPT);
                    }
                });
    }

    private void selectFile(int requestCode) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, requestCode);
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {

        ContentResolver contentResolver = getActivity().getContentResolver();

        if (resultCode == Activity.RESULT_OK) switch (requestCode) {

            case RC_HASH: {

                try {
                    InputStream fis = contentResolver.openInputStream(data.getData());

                    pBar.setMax(fis.available() / 1024);
                    pBar.setProgress(0);
                    pBar.setVisibility(View.VISIBLE);

                    eCryptHash.calculate(fis, ECryptHashAlgorithms.SHA_512,
                            new ECryptResultListener() {

                                @Override
                                public void onProgress(int newBytes, long bytesProcessed) {
                                    pBar.setProgress((int) bytesProcessed / 1024);
                                }

                                @Override
                                public <T> void onSuccess(final T result) {
                                    getActivity().runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            pBar.setVisibility(View.INVISIBLE);
                                            tvResult.setText((String) result);
                                        }
                                    });
                                }

                                @Override
                                public void onFailure(@NonNull final String message,
                                                      @NonNull final Exception e) {
                                    e.printStackTrace();
                                    getActivity().runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            pBar.setVisibility(View.INVISIBLE);
                                            Toast.makeText(getActivity(),
                                                    "Error: " + message,
                                                    Toast.LENGTH_SHORT).show();
                                        }
                                    });
                                }
                            });
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                    pBar.setVisibility(View.INVISIBLE);
                    Toast.makeText(getActivity(),
                            "File not found.", Toast.LENGTH_SHORT).show();
                } catch (IOException | NullPointerException e) {
                    pBar.setVisibility(View.INVISIBLE);
                    e.printStackTrace();
                }
                break;
            }

            case RC_ENCRYPT: {

                try {
                    final InputStream fis = contentResolver.openInputStream(data.getData());

                    pBar.setMax(fis.available() / 1024);
                    pBar.setProgress(0);
                    pBar.setVisibility(View.VISIBLE);

                    switch (rgType.getCheckedRadioButtonId()) {

                        case R.id.rbSymmetricF:
                            eCryptSymmetric.encrypt(fis, edPassword.getText().toString(),
                                    FileFragment.this);
                            break;

                        case R.id.rbAsymmetricF:
                            eCryptAsymmetric.generateKeyPair(new ECryptRSAKeyPairListener() {
                                @Override
                                public void onSuccess(@NotNull KeyPair keyPair) {
                                    privateKey = (RSAPrivateKey) keyPair.getPrivate();
                                    eCryptAsymmetric.encrypt(fis,
                                            (RSAPublicKey) keyPair.getPublic(),
                                            FileFragment.this);
                                }

                                @Override
                                public void onFailure(@NotNull final String message,
                                                      @NotNull Exception e) {
                                    e.printStackTrace();
                                    getActivity().runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            pBar.setVisibility(View.INVISIBLE);
                                            Toast.makeText(getActivity(),
                                                    message, Toast.LENGTH_LONG).show();
                                        }
                                    });
                                }
                            });
                            break;
                    }

                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                    pBar.setVisibility(View.INVISIBLE);
                    Toast.makeText(getActivity(),
                            "File not found.", Toast.LENGTH_SHORT).show();
                } catch (IOException | NullPointerException e) {
                    pBar.setVisibility(View.INVISIBLE);
                    e.printStackTrace();
                }
                break;
            }

            case RC_DECRYPT: {

                try {
                    InputStream fis = contentResolver.openInputStream(data.getData());

                    pBar.setMax(fis.available() / 1024);
                    pBar.setProgress(0);
                    pBar.setVisibility(View.VISIBLE);

                    switch (rgType.getCheckedRadioButtonId()) {

                        case R.id.rbSymmetricF:
                            eCryptSymmetric.decrypt(fis, edPassword.getText().toString(),
                                    FileFragment.this);
                            break;

                        case R.id.rbAsymmetricF:
                            eCryptAsymmetric.decrypt(fis, privateKey, FileFragment.this);
                            break;
                    }

                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                    pBar.setVisibility(View.INVISIBLE);
                    Toast.makeText(getActivity(),
                            "File not found.", Toast.LENGTH_SHORT).show();
                } catch (IOException | NullPointerException e) {
                    pBar.setVisibility(View.INVISIBLE);
                    e.printStackTrace();
                }
                break;
            }
        }
    }

    @Override
    public <T> void onSuccess(final T result) {
        getActivity().runOnUiThread(new Runnable() {
            @Override
            public void run() {
                pBar.setVisibility(View.INVISIBLE);
                tvResult.setText(getResources().getString(
                        R.string.success_file_encrypted,
                        ((File) result).getAbsolutePath()));
            }
        });
    }

    @Override
    public void onFailure(@NotNull final String message, @NotNull Exception e) {
        e.printStackTrace();
        getActivity().runOnUiThread(new Runnable() {
            @Override
            public void run() {
                pBar.setVisibility(View.INVISIBLE);
                Toast.makeText(getActivity(),
                        "Error: " + message,
                        Toast.LENGTH_SHORT).show();
            }
        });
    }

    @Override
    public void onProgress(int newBytes, final long bytesProcessed) {
        getActivity().runOnUiThread(new Runnable() {
            @Override
            public void run() {
                pBar.setProgress((int) bytesProcessed / 1024);
            }
        });
    }
}
