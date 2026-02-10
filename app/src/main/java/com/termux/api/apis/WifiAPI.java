package com.termux.api.apis;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.location.LocationManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiNetworkSpecifier;
import android.os.Build;
import android.text.TextUtils;
import android.text.format.Formatter;
import android.util.JsonWriter;

import com.termux.api.TermuxApiReceiver;
import com.termux.api.util.ResultReturner;
import com.termux.shared.logger.Logger;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

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

                    // Validate SSID or BSSID is provided
                    if (TextUtils.isEmpty(ssid) && TextUtils.isEmpty(bssid)) {
                        out.name("success").value(false);
                        out.name("message").value("Missing required parameters: ssid or bssid");
                        out.endObject();
                        return;
                    }

                    // Get security type from intent (optional)
                    String securityType = intent.getStringExtra("security_type");
                    if (TextUtils.isEmpty(securityType)) {
                        securityType = "WPA2"; // Default to WPA2
                    }

                    // Validate password only if not OPEN network
                    if (!securityType.equalsIgnoreCase("OPEN") && TextUtils.isEmpty(password)) {
                        out.name("success").value(false);
                        out.name("message").value("Password required for " + securityType + " network");
                        out.endObject();
                        return;
                    }

                    // If SSID not provided but BSSID is, try to find the SSID from scan results
                    if (TextUtils.isEmpty(ssid) && !TextUtils.isEmpty(bssid)) {
                        // Check if location is enabled (required for scan results)
                        if (!isLocationEnabled(context)) {
                            out.name("success").value(false);
                            out.name("message").value("Location service needs to be enabled to lookup network by BSSID");
                            out.endObject();
                            return;
                        }

                        List<ScanResult> scans = manager.getScanResults();
                        if (scans != null && !scans.isEmpty()) {
                            for (ScanResult scan : scans) {
                                if (bssid.equalsIgnoreCase(scan.BSSID)) {
                                    ssid = scan.SSID;
                                    break;
                                }
                            }
                        }

                        if (TextUtils.isEmpty(ssid)) {
                            out.name("success").value(false);
                            out.name("message").value("Could not find network with BSSID: " + bssid + ". Make sure location is enabled and device scanned the network.");
                            out.endObject();
                            return;
                        }
                    }

                    // Clean up SSID (remove quotes if present)
                    if (ssid != null) {
                        ssid = ssid.replaceAll("\"", "");
                    }

                    // Use appropriate API based on Android version
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        // Android 10+ : Use WifiNetworkSpecifier
                        connectWifiAndroid10Plus(context, out, manager, ssid, password, securityType);
                    } else {
                        // Android < 10 : Use legacy WifiConfiguration
                        connectWifiLegacy(out, manager, ssid, password, securityType);
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

    /**
     * Connect WiFi using WifiNetworkSpecifier (Android 10+)
     */
    private static void connectWifiAndroid10Plus(Context context, JsonWriter out, WifiManager manager,
                                                  String ssid, String password, String securityType) throws Exception {
        Logger.logDebug(LOG_TAG, "Using WifiNetworkSpecifier (Android 10+) for connection");

        try {
            // WEP is not supported by WifiNetworkSpecifier (deprecated security)
            if (securityType.equalsIgnoreCase("WEP")) {
                // Fallback to legacy API for WEP
                Logger.logDebug(LOG_TAG, "WEP not supported by modern API, using legacy method");
                connectWifiLegacy(out, manager, ssid, password, securityType);
                return;
            }

            WifiNetworkSpecifier.Builder specBuilder = new WifiNetworkSpecifier.Builder();
            specBuilder.setSsid(ssid);

            // Set password based on security type
            if (securityType.equalsIgnoreCase("OPEN")) {
                // OPEN network, no password
            } else {
                // WPA/WPA2/WPA3 - use setWpa2Passphrase (works for WPA2 and WPA3)
                specBuilder.setWpa2Passphrase(password);
            }

            WifiNetworkSpecifier specifier = specBuilder.build();

            NetworkRequest.Builder requestBuilder = new NetworkRequest.Builder();
            requestBuilder.addTransportType(NetworkCapabilities.TRANSPORT_WIFI);
            requestBuilder.setNetworkSpecifier(specifier);
            NetworkRequest request = requestBuilder.build();

            ConnectivityManager connectivityManager =
                    (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);

            final boolean[] connected = {false};
            final Exception[] lastException = {null};
            final CountDownLatch latch = new CountDownLatch(1);

            ConnectivityManager.NetworkCallback networkCallback = new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(Network network) {
                    Logger.logDebug(LOG_TAG, "Network available, connection successful");
                    connected[0] = true;
                    latch.countDown();
                }

                @Override
                public void onUnavailable() {
                    Logger.logDebug(LOG_TAG, "Network unavailable, connection failed");
                    connected[0] = false;
                    latch.countDown();
                }
            };

            Logger.logDebug(LOG_TAG, "Requesting network connection to: " + ssid);
            connectivityManager.requestNetwork(request, networkCallback, 15000); // 15 second timeout

            // Wait for network callback with timeout
            boolean completed = latch.await(20, TimeUnit.SECONDS);

            if (connected[0]) {
                out.name("success").value(true);
                out.name("message").value("Connected to " + ssid);
            } else {
                out.name("success").value(false);
                String message = completed ? "Connection failed or user rejected" : "Connection request timed out";
                out.name("message").value(message);
            }

        } catch (Exception e) {
            Logger.logStackTraceWithMessage(LOG_TAG, "Error in connectWifiAndroid10Plus", e);
            out.name("success").value(false);
            out.name("message").value("Error: " + e.getMessage());
        }
    }

    /**
     * Connect WiFi using WifiConfiguration (Android < 10)
     * Note: This API is deprecated and has limited functionality on modern Android versions.
     */
    private static void connectWifiLegacy(JsonWriter out, WifiManager manager, String ssid,
                                          String password, String securityType) throws Exception {
        Logger.logDebug(LOG_TAG, "Using WifiConfiguration (legacy) for connection");

        try {
            // Create WiFi configuration
            WifiConfiguration wifiConfig = new WifiConfiguration();
            wifiConfig.SSID = "\"" + ssid + "\""; // SSID must be quoted

            // Set security type and password
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

                // Set password for WPA networks
                wifiConfig.preSharedKey = "\"" + password + "\"";
            }

            // Try to add network or update existing one
            int networkId = manager.addNetwork(wifiConfig);

            if (networkId == -1) {
                // addNetwork failed - might be due to platform restrictions on Android 10+
                // Try to find and update existing configuration
                List<WifiConfiguration> configured = manager.getConfiguredNetworks();
                if (configured != null) {
                    for (WifiConfiguration config : configured) {
                        if (config.SSID.equals("\"" + ssid + "\"")) {
                            networkId = config.networkId;
                            Logger.logDebug(LOG_TAG, "Found existing network with id: " + networkId);
                            break;
                        }
                    }
                }

                if (networkId == -1) {
                    out.name("success").value(false);
                    out.name("message").value("Failed to add/find network configuration. This may be due to Android version restrictions (Android 10+ requires system app for network management).");
                    return;
                }
            }

            // Enable the network
            manager.disconnect();
            boolean enableSuccess = manager.enableNetwork(networkId, true);

            if (enableSuccess) {
                // Try to connect
                boolean connectSuccess = manager.reconnect();
                out.name("success").value(connectSuccess);
                out.name("network_id").value(networkId);
                out.name("message").value(connectSuccess ? "Connection initiated successfully" : "Network enabled but connection may have failed");
            } else {
                out.name("success").value(false);
                out.name("network_id").value(networkId);
                out.name("message").value("Failed to enable network");
            }

        } catch (Exception e) {
            Logger.logStackTraceWithMessage(LOG_TAG, "Error in connectWifiLegacy", e);
            out.name("success").value(false);
            out.name("message").value("Error: " + e.getMessage());
        }
    }

}
