package com.pvryan.easycryptsample;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
import android.support.annotation.NonNull;
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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class FileFragment extends Fragment implements ECResultListener {

    private final int RC_HASH = 2;
    private final int RC_ENCRYPT = 3;
    private final int RC_DECRYPT = 4;
    private final int RC_SIGN = 5;
    private final int RC_VERIFY = 6;

    private ECSymmetric eCSymmetric = new ECSymmetric();
    private ECAsymmetric eCAsymmetric = new ECAsymmetric();
    private ECHash eCHash = new ECHash();
    private ECKeys eCKeys = new ECKeys();
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    private LinearLayout llSignVerifyF;
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

        llSignVerifyF = (LinearLayout) view.findViewById(R.id.llSignVerifyF);
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
                        llSignVerifyF.setVisibility(View.GONE);
                        break;
                    case R.id.rbAsymmetricF:
                        edPassword.setVisibility(View.GONE);
                        llSignVerifyF.setVisibility(View.VISIBLE);
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
        view.findViewById(R.id.buttonSelectSignF)
                .setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view1) {
                        selectFile(RC_SIGN);
                    }
                });
        view.findViewById(R.id.buttonSelectVerifyF)
                .setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view1) {
                        selectFile(RC_VERIFY);
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

                    eCHash.calculate(fis, ECHashAlgorithms.SHA_512,
                            new ECResultListener() {

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
                            eCSymmetric.encrypt(fis, edPassword.getText().toString(),
                                    FileFragment.this);
                            break;

                        case R.id.rbAsymmetricF:
                            eCKeys.genRSAKeyPair(new ECRSAKeyPairListener() {
                                @Override
                                public void onGenerated(@NotNull KeyPair keyPair) {
                                    privateKey = (RSAPrivateKey) keyPair.getPrivate();
                                    eCAsymmetric.encrypt(fis,
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
                            eCSymmetric.decrypt(fis, edPassword.getText().toString(),
                                    FileFragment.this);
                            break;

                        case R.id.rbAsymmetricF:
                            eCAsymmetric.decrypt(fis, privateKey, FileFragment.this);
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

            case RC_SIGN:
                try {
                    final File sigFile = new File(Environment.getExternalStorageDirectory(),
                            "ECryptSample/sample.sig");
                    if (sigFile.exists()) sigFile.delete();

                    final InputStream fis = contentResolver.openInputStream(data.getData());

                    pBar.setMax(fis.available() / 1024);
                    pBar.setProgress(0);
                    pBar.setVisibility(View.VISIBLE);

                    eCKeys.genRSAKeyPair(new ECRSAKeyPairListener() {
                        @Override
                        public void onFailure(@NotNull final String message, @NotNull Exception e) {
                            e.printStackTrace();
                            getActivity().runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    Toast.makeText(getActivity(),
                                            "Error: " + message,
                                            Toast.LENGTH_SHORT).show();
                                }
                            });
                        }

                        @Override
                        public void onGenerated(@NotNull KeyPair keyPair) {
                            publicKey = (RSAPublicKey) keyPair.getPublic();
                            eCAsymmetric.sign(fis,
                                    (RSAPrivateKey) keyPair.getPrivate(),
                                    FileFragment.this, sigFile);
                        }
                    }, ECAsymmetric.KeySizes._4096);

                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                    pBar.setVisibility(View.INVISIBLE);
                    Toast.makeText(getActivity(),
                            "File not found.", Toast.LENGTH_SHORT).show();
                } catch (NullPointerException | IOException e) {
                    pBar.setVisibility(View.INVISIBLE);
                    e.printStackTrace();
                }
                break;

            case RC_VERIFY:
                try {
                    InputStream fis = contentResolver.openInputStream(data.getData());

                    pBar.setMax(fis.available() / 1024);
                    pBar.setProgress(0);
                    pBar.setVisibility(View.VISIBLE);

                    eCAsymmetric.verify(fis, publicKey,
                            new File(Environment.getExternalStorageDirectory(),
                                    "ECryptSample/sample.sig"),
                            new ECVerifiedListener() {
                                @Override
                                public void onProgress(int newBytes, final long bytesProcessed) {
                                    getActivity().runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            pBar.setProgress((int) bytesProcessed / 1024);
                                        }
                                    });
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
                } catch (NullPointerException | IOException e) {
                    pBar.setVisibility(View.INVISIBLE);
                    e.printStackTrace();
                }
                break;
        }
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
