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

import com.pvryan.easycrypt.ECrypt;

import java.security.InvalidParameterException;

public class PasswordFragment extends Fragment {

    private ECrypt eCrypt = new ECrypt();

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
    public void onViewCreated(View view, @Nullable Bundle savedInstanceState) {

        TextView result = (TextView) view.findViewById(R.id.tvResult);
        EditText edCharacters = (EditText) view.findViewById(R.id.edChars);
        EditText edLength = (EditText) view.findViewById(R.id.edLength);

        view.findViewById(R.id.buttonSecureRandom).setOnClickListener(v -> {
            try {
                String symbols;
                if ((symbols = edCharacters.getText().toString()).length() > 0) {
                    result.setText(eCrypt.genSecureRandomPassword(
                            Integer.valueOf(edLength.getText().toString()),
                            symbols.toCharArray()));
                } else {
                    result.setText(eCrypt.genSecureRandomPassword(
                            Integer.valueOf(edLength.getText().toString())));
                }
            } catch (InvalidParameterException e) {
                e.printStackTrace();
                Toast.makeText(view.getContext(), e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
            }
        });

        view.findViewById(R.id.buttonRandomOrg).setOnClickListener(v ->

                eCrypt.genRandomOrgPassword(
                        Integer.valueOf(edLength.getText().toString()),
                        "43e7bf3d-1e81-4dcd-b335-1d9efc1661db",
                        new ECrypt.ECryptPasswordListener() {

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
                        }));
    }
}
