package com.pvryan.easycryptsample;

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

import com.pvryan.easycrypt.ECryptPasswordListener;
import com.pvryan.easycrypt.ECryptPasswords;

import java.security.InvalidParameterException;

public class PasswordFragment extends Fragment {

    private ECryptPasswords eCryptPasswords = new ECryptPasswords();

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

        final TextView result = (TextView) view.findViewById(R.id.tvResult);
        final EditText edCharacters = (EditText) view.findViewById(R.id.edChars);
        final EditText edLength = (EditText) view.findViewById(R.id.edLength);

        view.findViewById(R.id.buttonSecureRandom).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    String symbols;
                    if ((symbols = edCharacters.getText().toString()).length() > 0) {
                        result.setText(eCryptPasswords.genSecureRandomPassword(
                                Integer.valueOf(edLength.getText().toString()),
                                symbols.toCharArray()));
                    } else {
                        result.setText(eCryptPasswords.genSecureRandomPassword(
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
                    eCryptPasswords.genRandomOrgPassword(
                            Integer.valueOf(edLength.getText().toString()),
                            "",
                            new ECryptPasswordListener() {

                                @Override
                                public void onFailure(@NonNull String message, @NonNull Exception e) {
                                    Log.w(PasswordFragment.class.getSimpleName(), message);
                                    e.printStackTrace();
                                    Toast.makeText(view.getContext(), e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
                                }

                                @Override
                                public void onSuccess(@NonNull String password) {
                                    result.setText(password);
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
