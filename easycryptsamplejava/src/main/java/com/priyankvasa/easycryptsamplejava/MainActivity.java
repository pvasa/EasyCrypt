package com.priyankvasa.easycryptsamplejava;

import android.os.Bundle;

import com.pvryan.easycrypt.symmetric.ECSymmetric;

import java.util.concurrent.CancellationException;

import androidx.appcompat.app.AppCompatActivity;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlinx.coroutines.experimental.Deferred;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final Deferred<String> handler = new ECSymmetric().encrypt("test", "password");

        handler.invokeOnCompletion(new Function1<Throwable, Unit>() {
            @Override
            public Unit invoke(Throwable e) {
                if (e == null) {
                    // success
                    handler.getCompleted();
                } else if (e instanceof CancellationException) {
                    // this job was cancelled by handler.cancel()
                } else {
                    // the job threw exception e
                    e.getLocalizedMessage();
                }
                return Unit.INSTANCE;
            }
        });

        // cancel encryption
        handler.cancel(null);
    }
}
