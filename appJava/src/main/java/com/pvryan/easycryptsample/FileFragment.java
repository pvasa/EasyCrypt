package com.pvryan.easycryptsample;

import android.app.Activity;
import android.content.ContentResolver;
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
import android.widget.TextView;
import android.widget.Toast;

import com.pvryan.easycrypt.ECrypt;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

public class FileFragment extends Fragment {

    private final int RC_HASH = 2;
    private final int RC_ENCRYPT = 3;
    private final int RC_DECRYPT = 4;
    private ECrypt eCrypt = new ECrypt();
    private EditText edPassword;
    private TextView tvResult;
    private ProgressBar pBar;

    public FileFragment() {
    }

    /**
     * Returns a new instance of this fragment for the given section
     * number.
     */
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

        edPassword = getActivity().findViewById(R.id.edPasswordFile);
        tvResult = getActivity().findViewById(R.id.tvResultFile);
        pBar = getActivity().findViewById(R.id.progressBar);

        view.findViewById(R.id.buttonSelectHash)
                .setOnClickListener(view1 -> selectFile(RC_HASH));
        view.findViewById(R.id.buttonSelectEncrypt)
                .setOnClickListener(view1 -> selectFile(RC_ENCRYPT));
        view.findViewById(R.id.buttonSelectDecrypt)
                .setOnClickListener(view1 -> selectFile(RC_DECRYPT));
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

                    eCrypt.hash(fis, ECrypt.HashAlgorithms.SHA_512,
                            new ECrypt.ECryptResultListener() {

                                @Override
                                public void onProgress(int newBytes, long bytesProcessed) {
                                    pBar.setProgress((int) bytesProcessed / 1024);
                                }

                                @Override
                                public <T> void onSuccess(T result) {
                                    getActivity().runOnUiThread(() -> {
                                        pBar.setVisibility(View.INVISIBLE);
                                        tvResult.setText((String) result);
                                    });
                                }

                                @Override
                                public void onFailure(@NonNull String message,
                                                      @NonNull Exception e) {
                                    e.printStackTrace();
                                    getActivity().runOnUiThread(() -> {
                                        pBar.setVisibility(View.INVISIBLE);
                                        Toast.makeText(getActivity(),
                                                "Error: " + message,
                                                Toast.LENGTH_SHORT).show();
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

                    InputStream fis = contentResolver.openInputStream(data.getData());

                    pBar.setMax(fis.available() / 1024);
                    pBar.setProgress(0);
                    pBar.setVisibility(View.VISIBLE);

                    eCrypt.encrypt(fis, edPassword.getText().toString(),
                            new ECrypt.ECryptResultListener() {

                                @Override
                                public void onProgress(int newBytes, long bytesProcessed) {
                                    pBar.setProgress((int) bytesProcessed / 1024);
                                }

                                @Override
                                public void onFailure(@NonNull String message,
                                                      @NonNull Exception e) {
                                    e.printStackTrace();
                                    getActivity().runOnUiThread(() -> {
                                        pBar.setVisibility(View.INVISIBLE);
                                        Toast.makeText(getActivity(),
                                                "Error: " + message,
                                                Toast.LENGTH_SHORT).show();
                                    });
                                }

                                @Override
                                public <T> void onSuccess(T result) {
                                    getActivity().runOnUiThread(() -> {
                                        pBar.setVisibility(View.INVISIBLE);
                                        tvResult.setText(getResources().getString(
                                                R.string.success_file_encrypted,
                                                ((File) result).getAbsolutePath()));
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

            case RC_DECRYPT: {
                try {

                    InputStream fis = contentResolver.openInputStream(data.getData());

                    pBar.setMax(fis.available() / 1024);
                    pBar.setProgress(0);
                    pBar.setVisibility(View.VISIBLE);

                    eCrypt.decrypt(fis, edPassword.getText().toString(),
                            new ECrypt.ECryptResultListener() {

                                @Override
                                public void onProgress(int newBytes, long bytesProcessed) {
                                    pBar.setProgress((int) bytesProcessed / 1024);
                                }

                                @Override
                                public void onFailure(@NonNull String message,
                                                      @NonNull Exception e) {
                                    e.printStackTrace();
                                    getActivity().runOnUiThread(() -> {
                                        pBar.setVisibility(View.INVISIBLE);
                                        Toast.makeText(getActivity(),
                                                "Error: " + message,
                                                Toast.LENGTH_SHORT).show();
                                    });
                                }

                                @Override
                                public <T> void onSuccess(T result) {
                                    getActivity().runOnUiThread(() -> {
                                        pBar.setVisibility(View.INVISIBLE);
                                        tvResult.setText(getResources().getString(
                                                R.string.success_file_decrypted,
                                                ((File) result).getAbsolutePath()));
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
        }
    }
}
