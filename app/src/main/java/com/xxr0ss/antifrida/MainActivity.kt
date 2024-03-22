package com.xxr0ss.antifrida

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.util.Log
import android.view.View
import android.widget.AdapterView
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.xxr0ss.antifrida.databinding.ActivityMainBinding
import com.xxr0ss.antifrida.utils.AntiFrida2
import com.xxr0ss.antifrida.utils.AntiFridaUtil
import com.xxr0ss.antifrida.utils.ReadVia
import com.xxr0ss.antifrida.utils.SuperUser
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream


class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val TAG = "MainActivity"

    private var posReadVia: Int = 0

    // put possible frida module names here
    private val frida_module_blocklist = listOf("frida-agent", "frida-gadget")

    @RequiresApi(Build.VERSION_CODES.R)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

//        System.loadLibrary("native-lib")
        AntiFrida2().checkBeingDebugged()
        SuperUser.tryRoot(packageCodePath)
        binding.rootStatus.text = "rooted: ${SuperUser.rooted.toString()}"

        binding.spinnerVia.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, pos: Int, id: Long) {
                posReadVia = pos
                Log.d(TAG, "onItemSelected: $pos $id")
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {
                Log.d(TAG, "onNothingSelected: null")
            }
        }

        binding.btnCheckMaps.setOnClickListener {
            Toast.makeText(
                this,
                (if (AntiFridaUtil.checkFridaByProcMaps(
                        frida_module_blocklist,
                        ReadVia.fromInt(posReadVia)
                    )
                )
                    "frida module detected" else "No frida module detected")
                        + " via ${ReadVia.fromInt(posReadVia).name}",
                Toast.LENGTH_SHORT
            ).show()
            binding.textStatus.editableText.clear()
            binding.textStatus.editableText.append(
                when (AntiFridaUtil.maps_file_content) {
                    null -> "no maps file data"
                    else -> "maps file:\n ${AntiFridaUtil.maps_file_content}"
                }
            )
        }

        binding.btnCheckPort.setOnClickListener {
            Toast.makeText(
                this, if (AntiFridaUtil.checkFridaByPort(27042))
                    "frida default port 27042 detected" else "no frida default port detected",
                Toast.LENGTH_SHORT
            ).show()
        }

        binding.btnCheckProcesses.setOnClickListener {
            if (!SuperUser.rooted) {
                SuperUser.tryRoot(packageCodePath)
                if (!SuperUser.rooted)
                    return@setOnClickListener
            }
            val result = SuperUser.execRootCmd("ps -ef")
            Log.i(TAG, "Root cmd result (size ${result.length}): $result ")
            binding.textStatus.text.clear()
            binding.textStatus.text.append(result)

            Toast.makeText(
                this, if (result.contains("frida-server"))
                    "frida-server process detected" else "no frida-server process found",
                Toast.LENGTH_SHORT
            ).show()
        }

        binding.btnScanModules.setOnClickListener {
            val useMySyscalls = binding.switchUseMySyscalls.isChecked
            // not all signatures here exist in the latest frida modules
            // if you find any signature that works, just put it here
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.READ_EXTERNAL_STORAGE), 1)
            if (!Environment.isExternalStorageManager()) {
                val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                startActivity(intent)
            }
            var txt = read_file("/sdcard/Download/files_fd/","frida_script.js")
            if (txt != null) {
                Log.d("frida-OOOK",txt)
            };
            val blockList = listOf("frida")
            var detected = false;
            blockList.forEach {
                detected = AntiFridaUtil.scanModulesForSignature(it, useMySyscalls)
            }

            Toast.makeText(
                this, if (detected)
                    "frida signature found" else "no frida signature found", Toast.LENGTH_SHORT
            ).show()
        }

        binding.btnCheckBeingDebugged.setOnClickListener {
            val useMySyscalls = binding.switchUseMySyscalls.isChecked
            Toast.makeText(
                this, if (AntiFridaUtil.checkBeingDebugged(useMySyscalls))
                    "Being debugged" else "Not being debugged", Toast.LENGTH_SHORT
            ).show()
        }

        binding.btnCheckPmap.setOnClickListener {
            if (!SuperUser.rooted) {
                SuperUser.tryRoot(packageCodePath)
                if (!SuperUser.rooted)
                    return@setOnClickListener
            }

            val result = SuperUser.execRootCmd("pmap ${android.os.Process.myPid()}")
            Log.i(TAG, "Root cmd result (size ${result.length}): $result ")
            binding.textStatus.text.clear()
            binding.textStatus.text.append(result)
            var moduleExists = false
            for (module in frida_module_blocklist) {
                if (result.contains(module)) {
                    moduleExists = true
                }
            }

            Toast.makeText(
                this, if (moduleExists)
                    "frida module detected" else "no frida module found",
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    fun read_file(path: String?, file: String?): String? {
        try {
            val fs = FileInputStream(File(path, file))
            val byteArrayOutputStream = ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            var len = 0
            while (fs.read(buffer).also { len = it } != -1) {
                byteArrayOutputStream.write(buffer, 0, len)
            }
            return byteArrayOutputStream.toString()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return ""
    }
}