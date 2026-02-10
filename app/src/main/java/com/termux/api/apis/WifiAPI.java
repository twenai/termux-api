package com.termux.api.apis;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.location.LocationManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.text.TextUtils;
import android.text.format.Formatter;
import android.util.JsonWriter;

import com.termux.api.TermuxApiReceiver;
import com.termux.api.util.ResultReturner;
import com.termux.shared.logger.Logger;

import java.util.List;

public class WifiAPI {

    private static final String LOG_TAG = "WifiAPI";

    public static void onReceiveWifiConnectionInfo(TermuxApiReceiver apiReceiver, final Context context, final Intent intent) {
        Logger.logDebug(LOG_TAG, "onReceiveWifiConnectionInfo");

        ResultReturner.returnData(apiReceiver, intent, new ResultReturner.ResultJsonWriter() {
            @SuppressLint("HardwareIds")
            @Override
            public void writeJson(JsonWriter out) throws Exception {
                WifiManager manager = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                WifiInfo info = manager.getConnectionInfo();
                out.beginObject();
                if (info == null) {
                    out.name("API_ERROR").value("No current connection");
                } else {
                    out.name("bssid").value(info.getBSSID());
                    out.name("frequency_mhz").value(info.getFrequency());
                    //noinspection deprecation - formatIpAddress is deprecated, but we only have a ipv4 address here:
                    out.name("ip").value(Formatter.formatIpAddress(info.getIpAddress()));
                    out.name("link_speed_mbps").value(info.getLinkSpeed());
                    out.name("mac_address").value(info.getMacAddress());
                    out.name("network_id").value(info.getNetworkId());
                    out.name("rssi").value(info.getRssi());
                    out.name("ssid").value(info.getSSID().replaceAll("\"", ""));
                    out.name("ssid_hidden").value(info.getHiddenSSID());
                    out.name("supplicant_state").value(info.getSupplicantState().toString());
                }
                out.endObject();
            }
        });
    }

    static boolean isLocationEnabled(Context context) {
        LocationManager lm = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        return lm.isProviderEnabled(LocationManager.GPS_PROVIDER);
    }

    public static void onReceiveWifiScanInfo(TermuxApiReceiver apiReceiver, final Context context, final Intent intent) {
        Logger.logDebug(LOG_TAG, "onReceiveWifiScanInfo");

        ResultReturner.returnData(apiReceiver, intent, new ResultReturner.ResultJsonWriter() {
            @Override
            public void writeJson(JsonWriter out) throws Exception {
                WifiManager manager = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                List<ScanResult> scans = manager.getScanResults();
                if (scans == null) {
                    out.beginObject().name("API_ERROR").value("Failed getting scan results").endObject();
                } else if (scans.isEmpty() && !isLocationEnabled(context)) {
                    // https://issuetracker.google.com/issues/37060483:
                    // "WifiManager#getScanResults() returns an empty array list if GPS is turned off"
                    String errorMessage = "Location needs to be enabled on the device";
                    out.beginObject().name("API_ERROR").value(errorMessage).endObject();
                } else {
                    out.beginArray();
                    for (ScanResult scan : scans) {
                        out.beginObject();
                        out.name("bssid").value(scan.BSSID);
                        out.name("frequency_mhz").value(scan.frequency);
                        out.name("rssi").value(scan.level);
                        out.name("ssid").value(scan.SSID);
                        out.name("timestamp").value(scan.timestamp);

                        int channelWidth = scan.channelWidth;
                        String channelWidthMhz = "???";
                        switch (channelWidth) {
                            case ScanResult.CHANNEL_WIDTH_20MHZ:
                                channelWidthMhz = "20";
                                break;
                            case ScanResult.CHANNEL_WIDTH_40MHZ:
                                channelWidthMhz = "40";
                                break;
                            case ScanResult.CHANNEL_WIDTH_80MHZ:
                                channelWidthMhz = "80";
                                break;
                            case ScanResult.CHANNEL_WIDTH_80MHZ_PLUS_MHZ:
                                channelWidthMhz = "80+80";
                                break;
                            case ScanResult.CHANNEL_WIDTH_160MHZ:
                                channelWidthMhz = "160";
                                break;
                        }
                        out.name("channel_bandwidth_mhz").value(channelWidthMhz);
                        if (channelWidth != ScanResult.CHANNEL_WIDTH_20MHZ) {
                            // centerFreq0 says "Not used if the AP bandwidth is 20 MHz".
                            out.name("center_frequency_mhz").value(scan.centerFreq0);
                        }
                        if (!TextUtils.isEmpty(scan.capabilities)) {
                            out.name("capabilities").value(scan.capabilities);
                        }
                        if (!TextUtils.isEmpty(scan.operatorFriendlyName)) {
                            out.name("operator_name").value(scan.operatorFriendlyName.toString());
                        }
                        if (!TextUtils.isEmpty(scan.venueName)) {
                            out.name("venue_name").value(scan.venueName.toString());
                        }
                        out.endObject();
                    }
                    out.endArray();
                }
            }
        });
    }

    public static void onReceiveWifiEnable(TermuxApiReceiver apiReceiver, final Context context, final Intent intent) {
        Logger.logDebug(LOG_TAG, "onReceiveWifiEnable");

        ResultReturner.returnData(apiReceiver, intent, new ResultReturner.ResultJsonWriter() {
            @Override
            public void writeJson(JsonWriter out) {
                WifiManager manager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
                boolean state = intent.getBooleanExtra("enabled", false);
                manager.setWifiEnabled(state);
            }
        });
    }

    public static void onReceiveWifiConnect(TermuxApiReceiver apiReceiver, final Context context, final Intent intent) {
        Logger.logDebug(LOG_TAG, "onReceiveWifiConnect");

        ResultReturner.returnData(apiReceiver, intent, new ResultReturner.ResultJsonWriter() {
            @Override
            public void writeJson(JsonWriter out) throws Exception {
                WifiManager manager = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                out.beginObject();

                try {
                    // Get SSID or BSSID from intent
                    String ssid = intent.getStringExtra("ssid");
                    String bssid = intent.getStringExtra("bssid");
                    String password = intent.getStringExtra("password");

                    // Validate input
                    if ((TextUtils.isEmpty(ssid) && TextUtils.isEmpty(bssid)) || TextUtils.isEmpty(password)) {
                        out.name("success").value(false);
                        out.name("message").value("Missing required parameters: ssid/bssid and password");
                        out.endObject();
                        return;
                    }

                    // If SSID not provided but BSSID is, try to find the SSID from scan results
                    if (TextUtils.isEmpty(ssid) && !TextUtils.isEmpty(bssid)) {
                        List<ScanResult> scans = manager.getScanResults();
                        if (scans != null) {
                            for (ScanResult scan : scans) {
                                if (bssid.equalsIgnoreCase(scan.BSSID)) {
                                    ssid = scan.SSID;
                                    break;
                                }
                            }
                        }
                        if (TextUtils.isEmpty(ssid)) {
                            out.name("success").value(false);
                            out.name("message").value("Could not find network with BSSID: " + bssid);
                            out.endObject();
                            return;
                        }
                    }

                    // Clean up SSID (remove quotes if present)
                    ssid = ssid.replaceAll("\"", "");

                    // Get security type from intent (optional)
                    String securityType = intent.getStringExtra("security_type");
                    if (TextUtils.isEmpty(securityType)) {
                        securityType = "WPA2"; // Default to WPA2
                    }

                    // Create WiFi configuration
                    WifiConfiguration wifiConfig = new WifiConfiguration();
                    wifiConfig.SSID = "\"" + ssid + "\""; // SSID must be quoted
                    wifiConfig.preSharedKey = "\"" + password + "\""; // Password must be quoted

                    // Set security type
                    if (securityType.equalsIgnoreCase("OPEN")) {
                        wifiConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
                    } else if (securityType.equalsIgnoreCase("WEP")) {
                        wifiConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
                        wifiConfig.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
                        wifiConfig.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.SHARED);
                        // WEP password handling
                        if (password.matches("[0-9A-Fa-f]+")) {
                            wifiConfig.wepKeys[0] = password;
                        } else {
                            wifiConfig.wepKeys[0] = "\"" + password + "\"";
                        }
                        wifiConfig.wepTxKeyIndex = 0;
                    } else {
                        // Default to WPA/WPA2
                        wifiConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
                        wifiConfig.allowedProtocols.set(WifiConfiguration.Protocol.WPA);
                        wifiConfig.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
                        wifiConfig.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
                        wifiConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
                        wifiConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
                        wifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
                        wifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
                    }

                    // Add the network and get its network ID
                    int networkId = manager.addNetwork(wifiConfig);
                    if (networkId == -1) {
                        out.name("success").value(false);
                        out.name("message").value("Failed to add network configuration");
                        out.endObject();
                        return;
                    }

                    // Enable the network
                    manager.disconnect();
                    boolean success = manager.enableNetwork(networkId, true);

                    if (success) {
                        // Try to connect
                        boolean connectSuccess = manager.reconnect();
                        out.name("success").value(connectSuccess);
                        out.name("network_id").value(networkId);
                        out.name("message").value(connectSuccess ? "Connection initiated successfully" : "Network enabled but connection failed");
                    } else {
                        out.name("success").value(false);
                        out.name("network_id").value(networkId);
                        out.name("message").value("Failed to enable network");
                    }

                } catch (Exception e) {
                    Logger.logStackTraceWithMessage(LOG_TAG, "Error in onReceiveWifiConnect", e);
                    out.name("success").value(false);
                    out.name("message").value("Error: " + e.getMessage());
                }

                out.endObject();
            }
        });
    }

}
