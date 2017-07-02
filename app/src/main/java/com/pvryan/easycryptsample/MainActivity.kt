package com.pvryan.easycryptsample

import android.Manifest
import android.os.Bundle
import android.os.Environment
import android.support.v4.app.Fragment
import android.support.v4.app.FragmentManager
import android.support.v4.app.FragmentPagerAdapter
import android.support.v4.view.ViewPager
import android.support.v7.app.AppCompatActivity
import android.view.Menu
import android.view.MenuItem
import com.pvryan.easycrypt.ECrypt
import com.pvryan.easycryptsample.extensions.checkPermissions
import com.pvryan.easycryptsample.extensions.handlePermissionResults
import kotlinx.android.synthetic.main.activity_main.*
import java.io.File
import java.io.FileWriter

class MainActivity : AppCompatActivity() {

    private val RC_PERMISSIONS = 1
    private val eCrypt = ECrypt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(toolbar)

        viewPager.adapter = SectionsPagerAdapter(supportFragmentManager)

        viewPager.addOnPageChangeListener(object : ViewPager.OnPageChangeListener {
            override fun onPageScrollStateChanged(state: Int) {}

            override fun onPageScrolled(position: Int, positionOffset: Float, positionOffsetPixels: Int) {}

            override fun onPageSelected(position: Int) {

            }

        })

        val tempFile = File(Environment.getExternalStorageDirectory().absolutePath, "/test.txt")
        if (!tempFile.exists()) {
            val writer = FileWriter(tempFile)
            writer.write("Test data to be encrypted.")
            writer.flush()
            writer.close()
        }

    }

    /***************** Options menu *****************/
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        return when (item.itemId) {
            R.id.action_settings -> true
            else -> super.onOptionsItemSelected(item)
        }
    }

    /***************** App permissions *****************/
    override fun onResume() {
        super.onResume()
        checkPermissions(RC_PERMISSIONS,
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            RC_PERMISSIONS -> handlePermissionResults(requestCode, permissions, grantResults)
        }
    }

    private inner class SectionsPagerAdapter(fm: FragmentManager) : FragmentPagerAdapter(fm) {
        override fun getCount(): Int {
            return 2
        }

        override fun getItem(position: Int): Fragment {
            when (position) {
                0 -> return FragmentString.newInstance()
                1 -> return FragmentFile.newInstance()
                else -> return Fragment()
            }
        }

    }
}
