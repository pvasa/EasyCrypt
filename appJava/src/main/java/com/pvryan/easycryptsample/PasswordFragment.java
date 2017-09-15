package com.pvryan.easycryptsample;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.pvryan.easycrypt.ECKeys;
import com.pvryan.easycrypt.symmetric.ECPasswordListener;

import java.security.InvalidParameterException;

public class PasswordFragment extends Fragment {

    private ECKeys ECKeys = new ECKeys();

    private TextView tvResult;
    private EditText edCharacters, edLength;

    private ClipboardManager clipboard;

    public PasswordFragment() {
    }

    /**
     * Returns a new instance of this fragment for the given section
     * number.
     */
    public static PasswordFragment newInstance() {
        return new PasswordFragment();
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_password, container, false);
    }

    @Override
    public void onViewCreated(final View view, @Nullable Bundle savedInstanceState) {

        clipboard = (ClipboardManager) getActivity().getSystemService(Context.CLIPBOARD_SERVICE);

        tvResult = (TextView) view.findViewById(R.id.tvResult);
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

        edCharacters = (EditText) view.findViewById(R.id.edChars);
        edLength = (EditText) view.findViewById(R.id.edLength);

        view.findViewById(R.id.buttonSecureRandom).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    String symbols;
                    if ((symbols = edCharacters.getText().toString()).length() > 0) {
                        tvResult.setText(ECKeys.genSecureRandomPassword(
                                Integer.valueOf(edLength.getText().toString()),
                                symbols.toCharArray()));
                    } else {
                        tvResult.setText(ECKeys.genSecureRandomPassword(
                                Integer.valueOf(edLength.getText().toString())));
                    }
                } catch (InvalidParameterException e) {
                    e.printStackTrace();
                    Toast.makeText(view.getContext(), e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
                } catch (NumberFormatException e) {
                    e.printStackTrace();
                    Toast.makeText(v.getContext(),
                            "Too big number.", Toast.LENGTH_SHORT).show();
                }
            }
        });

        view.findViewById(R.id.buttonRandomOrg).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                try {
                    ECKeys.genRandomOrgPassword(
                            Integer.valueOf(edLength.getText().toString()),
                            "",
                            new ECPasswordListener() {

                                @Override
                                public void onFailure(@NonNull String message, @NonNull Exception e) {
                                    Log.w(PasswordFragment.class.getSimpleName(), message);
                                    e.printStackTrace();
                                    Toast.makeText(view.getContext(), e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
                                }

                                @Override
                                public void onGenerated(@NonNull String password) {
                                    tvResult.setText(password);
                                }
                            });
                } catch (NumberFormatException e) {
                    e.printStackTrace();
                    Toast.makeText(v.getContext(),
                            "Too big number.", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }
}
