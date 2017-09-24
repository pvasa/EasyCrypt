package com.pvryan.easycryptsample;

import android.animation.ObjectAnimator;
import android.annotation.SuppressLint;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.DecelerateInterpolator;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.pvryan.easycrypt.ECKeys;
import com.pvryan.easycrypt.symmetric.ECPasswordAnalysis;
import com.pvryan.easycrypt.symmetric.ECPasswordAnalyzer;
import com.pvryan.easycrypt.symmetric.ECPasswordListener;

import java.security.InvalidParameterException;
import java.util.Locale;

public class PasswordFragment extends Fragment {

    private ECKeys ECKeys = new ECKeys();

    private TextView tvResult;
    private EditText edCharacters, edLength;

    private ClipboardManager clipboard;

    public PasswordFragment() {
    }

    /**
     * Returns a new instance of this fragment for the given section number.
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

        tvResult = view.findViewById(R.id.tvResultP);
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

        edCharacters = view.findViewById(R.id.edCharsP);
        edLength = view.findViewById(R.id.edLengthP);

        final TextView tvGuesses = view.findViewById(R.id.tvGuesses);
        final TextView tvGuessesLog10 = view.findViewById(R.id.tvGuessesLog10);
        final TextView tvCalcTime = view.findViewById(R.id.tvCalcTime);
        final TextView tvOnlineBFTime = view.findViewById(R.id.tvOnlineBFTime);
        final TextView tvOfflineBFTime = view.findViewById(R.id.tvOfflineBFTime);
        final TextView tvWarning = view.findViewById(R.id.tvWarning);

        final ProgressBar progressBarP = view.findViewById(R.id.progressBarP);

        final LinearLayout llAnalysis = view.findViewById(R.id.llAnalysis);
        EditText edPassword = view.findViewById(R.id.edPasswordP);
        edPassword.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            @Override
            public void onFocusChange(View view, boolean b) {
                if (b) llAnalysis.setVisibility(View.VISIBLE);
                else llAnalysis.setVisibility(View.GONE);
            }
        });
        edPassword.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override
            public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @SuppressLint("SetTextI18n")
            @Override
            public void afterTextChanged(Editable editable) {
                ECPasswordAnalysis analysis = ECPasswordAnalyzer.analyze(editable.toString());

                ObjectAnimator animation = ObjectAnimator.ofInt(
                        progressBarP, "progress",
                        analysis.getStrength().getValue() * 100);
                animation.setDuration(500); // 0.5 second
                animation.setInterpolator(new DecelerateInterpolator());
                animation.start();

                tvGuesses.setText(String.format(Locale.CANADA, "%.4f", analysis.getGuesses()));
                tvGuessesLog10.setText(String.format(Locale.CANADA, "%.4f", analysis.getGuessesLog10()));
                tvCalcTime.setText(String.format(Locale.CANADA, "%d", analysis.getCalcTime()) + " ms");
                tvOnlineBFTime.setText(
                        String.format(Locale.CANADA, "%.4f",
                                analysis.getCrackTimeSeconds().getOnlineThrottling100perHour()) +
                                " secs" + " (" + analysis.getCrackTimesDisplay().getOnlineThrottling100perHour() + ")");
                tvOfflineBFTime.setText(
                        String.format(Locale.CANADA, "%.4f",
                                analysis.getCrackTimeSeconds().getOfflineFastHashing1e10PerSecond()) +
                                " secs" + " (" + analysis.getCrackTimesDisplay().getOfflineFastHashing1e10PerSecond() + ")");
                tvWarning.setText(analysis.getFeedback().getWarning());
            }
        });

        view.findViewById(R.id.buttonSecureRandomP).setOnClickListener(new View.OnClickListener() {
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

        view.findViewById(R.id.buttonRandomOrgP).setOnClickListener(new View.OnClickListener() {
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
