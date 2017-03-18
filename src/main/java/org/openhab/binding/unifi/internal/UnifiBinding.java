/**
 * Copyright (c) 2010-2015, openHAB.org and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.unifi.internal;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang.StringUtils;
import org.openhab.binding.unifi.UnifiBindingProvider;
import org.openhab.core.binding.AbstractActiveBinding;
import org.openhab.core.items.ItemNotFoundException;
import org.openhab.core.items.ItemRegistry;
import org.openhab.core.library.types.OnOffType;
import org.openhab.core.library.types.StringType;
import org.openhab.core.types.Command;
import org.openhab.core.types.State;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Map;


/**
 * Implement this class if you are going create an actively polling service
 * like querying a Website/Device.
 *
 * @author Ondrej Pecta
 * @since 1.9.0
 */
public class UnifiBinding extends AbstractActiveBinding<UnifiBindingProvider> {

    private static final Logger logger =
            LoggerFactory.getLogger(UnifiBinding.class);
    private static final String LED = "led";
    private static final String REBOOT = "reboot";
    private static final String BLINK = "blink";
    private static final String DISABLE_AP = "disable_ap";
    private static final String ENABLE_WLAN = "enable_wlan";
    private static final String PASSWORD = "password";
    private static final String CHANGE_PASSWORD = "change_password";

    //generate password
    static final String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static SecureRandom rnd = new SecureRandom();

    /**
     * The BundleContext. This is only valid when the bundle is ACTIVE. It is set in the activate()
     * method and must not be accessed anymore once the deactivate() method was called or before activate()
     * was called.
     */
    private BundleContext bundleContext;
    private ItemRegistry itemRegistry;

    /**
     * the refresh interval which is used to poll values from the Unifi
     * server (optional, defaults to 60000ms)
     */
    private long refreshInterval = 60000;
    private String controllerIP = "";
    private String controllerPort = "";
    private String username = "";
    private String password = "";

    private SSLContext sc;

    //Gson parser
    private JsonParser parser = new JsonParser();

    public UnifiBinding() {
    }

    ArrayList<String> cookies = new ArrayList<>();
    ArrayList<String> aps = new ArrayList<>();

    /**
     * Called by the SCR to activate the component with its configuration read from CAS
     *
     * @param bundleContext BundleContext of the Bundle that defines this component
     * @param configuration Configuration properties for this component obtained from the ConfigAdmin service
     */
    public void activate(final BundleContext bundleContext, final Map<String, Object> configuration) {
        this.bundleContext = bundleContext;

        // the configuration is guaranteed not to be null, because the component definition has the
        // configuration-policy set to require. If set to 'optional' then the configuration may be null


        // to override the default refresh interval one has to add a
        // parameter to openhab.cfg like <bindingName>:refresh=<intervalInMs>
        readConfiguration(configuration);

        try {
            sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (Exception e) {
            logger.error("Cannot initialize SSL Context!" + e.toString());
            setProperlyConfigured(false);
            return;
        }

        setProperlyConfigured(true);
    }

    private void readConfiguration(Map<String, Object> configuration) {
        String refreshIntervalString = (String) configuration.get("refresh");
        if (StringUtils.isNotBlank(refreshIntervalString)) {
            refreshInterval = Long.parseLong(refreshIntervalString);
        }

        String controllerIPString = (String) configuration.get("controllerIP");
        if (StringUtils.isNotBlank(controllerIPString)) {
            controllerIP = controllerIPString;
        }

        String controllerPortString = (String) configuration.get("controllerPort");
        if (StringUtils.isNotBlank(controllerPortString)) {
            controllerPort = controllerPortString;
        }

        String usernameString = (String) configuration.get("username");
        if (StringUtils.isNotBlank(usernameString)) {
            username = usernameString;
        }

        String passwordString = (String) configuration.get("password");
        if (StringUtils.isNotBlank(passwordString)) {
            password = passwordString;
        }
    }

    private void enableWlan(String wlanId, boolean enable) {
        String url = getControllerUrl("api/s/default/rest/wlanconf/" + wlanId);
        String response = sendToController(url, "{'enabled': " + enable + "}", "PUT");
        logger.debug(response);
    }

    private void changePassword(String wlanId, String newPassword) {
        String url = getControllerUrl("api/s/default/rest/wlanconf/" + wlanId);
        String response = sendToController(url, "{'x_passphrase': '" + newPassword + "'}", "PUT");
        logger.debug(response);
    }

    private void discoverAPs() {
        aps.clear();
        String url = getControllerUrl("api/s/default/stat/device");
        String response = sendToController(url, "");

        if (response.equals(""))
            return;
        logger.debug(response);

        JsonObject jobject = parser.parse(response).getAsJsonObject();
        String res = jobject.get("meta").getAsJsonObject().get("rc").getAsString();
        if (res.equals("ok")) {
            JsonArray jarray = jobject.get("data").getAsJsonArray();
            logger.info("Detected " + jarray.size() + " unifi APs");
            for (JsonElement je : jarray) {
                jobject = je.getAsJsonObject();
                String _id = jobject.get("_id").getAsString();
                String mac = jobject.get("mac").getAsString();
                StringBuilder sb = new StringBuilder();
                sb.append("Unifi AP with id: " + _id + " MAC: " + mac);
                JsonArray vaparray = jobject.get("vap_table").getAsJsonArray();
                sb.append(" has " + vaparray.size() + " wifi networks:");
                for (JsonElement vapel : vaparray) {
                    String name = vapel.getAsJsonObject().get("name").getAsString();
                    String ssid = vapel.getAsJsonObject().get("essid").getAsString();
                    String id = vapel.getAsJsonObject().get("id").getAsString();
                    String radio = vapel.getAsJsonObject().get("radio").getAsString();

                    boolean guest = vapel.getAsJsonObject().get("is_guest").getAsBoolean();
                    sb.append("\n\t SSID: " + ssid);
                    sb.append(" name: " + name);
                    sb.append(" id: " + id);
                    sb.append(" radio: " + radio);
                    if (guest) {
                        sb.append(" (GUEST)");
                    }
                    aps.add(id);
                }
                logger.info(sb.toString());
            }
        }
    }

    private boolean login() {
        String url = null;

        try {
            url = getControllerUrl("api/login");
            String urlParameters = "{'username':'" + username + "','password':'" + password + "'}";
            byte[] postData = urlParameters.getBytes(StandardCharsets.UTF_8);

            URL cookieUrl = new URL(url);
            HttpsURLConnection connection = (HttpsURLConnection) cookieUrl.openConnection();
            connection.setDoOutput(true);
            connection.setInstanceFollowRedirects(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Referer", getControllerUrl("login"));
            connection.setRequestProperty("Content-Length", Integer.toString(postData.length));
            connection.setUseCaches(false);

            try (DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
                wr.write(postData);
            }

            //get cookie
            cookies.clear();
            String headerName;
            for (int i = 1; (headerName = connection.getHeaderFieldKey(i)) != null; i++) {
                if (headerName.equals("Set-Cookie")) {
                    cookies.add(connection.getHeaderField(i));
                }
            }

            InputStream response = connection.getInputStream();
            String line = readResponse(response);
            logger.debug("Unifi response: " + line);
            return checkResponse(line);
        } catch (MalformedURLException e) {
            logger.error("The URL '" + url + "' is malformed: " + e.toString());
        } catch (Exception e) {
            logger.error("Cannot get Ubiquiti Unifi login cookie: " + e.toString());
        }
        return false;
    }

    private boolean checkResponse(String line) {

        try {
            JsonObject jobject = parser.parse(line).getAsJsonObject();
            if (jobject != null) {
                jobject = jobject.get("meta").getAsJsonObject();
                return jobject.get("rc").getAsString().equals("ok");
            } else {
                return false;
            }
        } catch (Exception ex) {
            return false;
        }
    }

    TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }

                public void checkServerTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }
            }
    };

    private String readResponse(InputStream response) throws Exception {
        String line;
        StringBuilder body = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(response));

        while ((line = reader.readLine()) != null) {
            body.append(line).append("\n");
        }
        line = body.toString();
        logger.debug(line);
        return line;
    }

    private String getControllerUrl(String site) {
        return "https://" + controllerIP + ":" + controllerPort + "/" + site;
    }

    /**
     * Called by the SCR when the configuration of a binding has been changed through the ConfigAdmin service.
     *
     * @param configuration Updated configuration properties
     */
    public void modified(final Map<String, Object> configuration) {
        // update the internal configuration accordingly
    }

    /**
     * Called by the SCR to deactivate the component when either the configuration is removed or
     * mandatory references are no longer satisfied or the component has simply been stopped.
     *
     * @param reason Reason code for the deactivation:<br>
     *               <ul>
     *               <li> 0 – Unspecified
     *               <li> 1 – The component was disabled
     *               <li> 2 – A reference became unsatisfied
     *               <li> 3 – A configuration was changed
     *               <li> 4 – A configuration was deleted
     *               <li> 5 – The component was disposed
     *               <li> 6 – The bundle was stopped
     *               </ul>
     */
    public void deactivate(final int reason) {
        this.bundleContext = null;
        // deallocate resources here that are no longer needed and
        // should be reset when activating this binding again

        logout();
    }

    private void logout() {
        URL url = null;
        if (cookies.size() == 0)
            return;

        try {
            url = new URL(getControllerUrl("logout"));
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setInstanceFollowRedirects(true);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Cookie", cookies.get(0) + "; " + cookies.get(1));
            connection.getInputStream();
        } catch (MalformedURLException e) {
            logger.error("The URL '" + url + "' is malformed: " + e.toString());
        } catch (Exception e) {
            logger.error("Cannot do logout. Exception: " + e.toString());
        }
    }

    public void setItemRegistry(ItemRegistry itemRegistry) {
        this.itemRegistry = itemRegistry;
    }

    public void unsetItemRegistry(ItemRegistry itemRegistry) {
        this.itemRegistry = null;
    }

    /**
     * @{inheritDoc}
     */
    @Override
    protected long getRefreshInterval() {
        return refreshInterval;
    }

    /**
     * @{inheritDoc}
     */
    @Override
    protected String getName() {
        return "Unifi Refresh Service";
    }

    /**
     * @{inheritDoc}
     */
    @Override
    protected void execute() {
        // the frequently executed code (polling) goes here ...
        logger.debug("execute() method is called!");

        if (!bindingsExist())
            return;

        login();
        if (aps.size() == 0) {
            discoverAPs();
        }

        for (final UnifiBindingProvider provider : providers) {
            for (final String itemName : provider.getItemNames()) {
                if (provider.getItemType(itemName).equals(LED)) {
                    readLedStatus(itemName);
                }
                if (provider.getItemType(itemName).equals(ENABLE_WLAN)) {
                    readWlanStatus(itemName, provider.getItemId(itemName));
                }
                if (provider.getItemType(itemName).equals(PASSWORD)) {
                    readWlanPassword(itemName, provider.getItemId(itemName));
                }
            }

        }
    }

    private void readWlanStatus(String itemName, String id) {
        String url = getControllerUrl("api/s/default/rest/wlanconf/" + id);
        String response = sendToController(url, "", "GET");
        logger.debug(response);
        if (checkResponse(response)) {
            JsonObject jobject = parser.parse(response).getAsJsonObject();
            if (jobject != null) {
                JsonArray jarray = jobject.getAsJsonArray("data");
                if (jarray.size() == 0) {
                    logger.error("Cannot read wlan status for id: " + id);
                    return;
                }
                jobject = jarray.get(0).getAsJsonObject();
                boolean enabled = jobject.get("enabled").getAsBoolean();
                State newVal = enabled ? OnOffType.ON : OnOffType.OFF;
                State oldVal;
                try {
                    oldVal = itemRegistry.getItem(itemName).getState();
                    if (!newVal.equals(oldVal))
                        eventPublisher.postUpdate(itemName, newVal);
                } catch (ItemNotFoundException e) {
                    logger.error("Cannot find item " + itemName + " in item registry!");
                }
            } else {
                logger.error("Cannot parse JSON response!");
            }
        }
    }

    private void readWlanPassword(String itemName, String id) {
        String url = getControllerUrl("api/s/default/rest/wlanconf/" + id);
        String response = sendToController(url, "", "GET");
        logger.debug(response);
        if (checkResponse(response)) {
            JsonObject jobject = parser.parse(response).getAsJsonObject();
            if (jobject != null) {
                JsonArray jarray = jobject.getAsJsonArray("data");
                if (jarray.size() == 0) {
                    logger.error("Cannot read wlan password for id: " + id);
                    return;
                }
                jobject = jarray.get(0).getAsJsonObject();
                String password = jobject.get("x_passphrase").getAsString();
                State newVal = new StringType(password);
                State oldVal;
                try {
                    oldVal = itemRegistry.getItem(itemName).getState();
                    if (!newVal.equals(oldVal))
                        eventPublisher.postUpdate(itemName, newVal);
                } catch (ItemNotFoundException e) {
                    logger.error("Cannot find item " + itemName + " in item registry!");
                }
            } else {
                logger.error("Cannot parse JSON response!");
            }
        }
    }

    private void readLedStatus(String itemName) {
        String url = getControllerUrl("api/s/default/set/setting/mgmt");
        String response = sendToController(url, "");
        logger.debug(response);
        if (checkResponse(response)) {
            JsonObject jobject = parser.parse(response).getAsJsonObject();
            if (jobject != null) {
                JsonArray jarray = jobject.getAsJsonArray("data");
                if (jarray.size() == 0) {
                    logger.error("Cannot read led status for item: " + itemName);
                    return;
                }
                jobject = jarray.get(0).getAsJsonObject();
                boolean enabled = jobject.get("led_enabled").getAsBoolean();
                State newVal = enabled ? OnOffType.ON : OnOffType.OFF;
                State oldVal;
                try {
                    oldVal = itemRegistry.getItem(itemName).getState();
                    if (!newVal.equals(oldVal))
                        eventPublisher.postUpdate(itemName, newVal);
                } catch (ItemNotFoundException e) {
                    logger.error("Cannot find item " + itemName + " in item registry!");
                }
            } else {
                logger.error("Cannot parse JSON response!");
            }
        }

    }

    /**
     * @{inheritDoc}
     */
    @Override
    protected void internalReceiveCommand(String itemName, Command command) {
        // the code being executed when a command was sent on the openHAB
        // event bus goes here. This method is only called if one of the
        // BindingProviders provide a binding for the given 'itemName'.
        logger.debug("internalReceiveCommand({},{}) is called!", itemName, command);
        UnifiGenericBindingProvider.UnifiBindingConfig config = getUnifiConfig(itemName);
        if (config == null)
            return;

        String type = config.getType();
        switch (type) {
            case LED:
                switchLed(command.equals(OnOffType.ON));
                break;
            case REBOOT:
                if (command.equals(OnOffType.ON))
                    rebootAP(config.getId());
                break;
            case BLINK:
                blinkLed(config.getId(), command.equals(OnOffType.ON));
                break;
            case DISABLE_AP:
                disableAP(config.getId(), command.equals(OnOffType.ON));
                break;
            case ENABLE_WLAN:
                enableWlan(config.getId(), command.equals(OnOffType.ON));
                break;
            case CHANGE_PASSWORD:
                if (command.equals(OnOffType.ON)) {
                    changePassword(config.getId(), generatePassword(10));
                }
                break;
            default:
                logger.error("Unknown Unifi type: " + type + " for item " + itemName);
        }

        /*
        if (type.equals(LED)) {
            switchLed(command.toString().equals("ON"));
        }
        else if (type.equals(REBOOT)) {
            if( command.toString().equals("ON") )
                reboot(config.getId());
        } else
            //
            if (type.equals(BLINK)) {
                blinkLed(config.getId(), command.toString().equals("ON"));
            } else {
                logger.error("Unknown Unifi type: " + type + " for item " + itemName);
            }
        */
    }

    private String generatePassword(int len) {
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++)
            sb.append(AB.charAt(rnd.nextInt(AB.length())));
        return sb.toString();
    }

    private void disableAP(String id, boolean disable) {
        String url = getControllerUrl("api/s/default/rest/device/" + id);
        String urlParameters = "{'disabled':" + disable + "}";
        sendToController(url, urlParameters, "PUT");
    }

    private void rebootAP(String mac) {
        String url = getControllerUrl("api/s/default/cmd/devmgr");
        String urlParameters = "json={'cmd':'restart', 'mac':'" + mac + "'}";
        sendToController(url, urlParameters);
    }

    private void blinkLed(String mac, boolean value) {
        String url = getControllerUrl("api/s/default/cmd/devmgr");
        String urlParameters = "json={'cmd':'" + (value ? "" : "un") + "set-locate', 'mac':'" + mac + "'}";
        sendToController(url, urlParameters);
    }

    private void switchLed(boolean value) {
        String url = getControllerUrl("api/s/default/set/setting/mgmt");
        String urlParameters = "json={'led_enabled':" + value + "}";
        sendToController(url, urlParameters);
    }

    private String sendToController(String url, String urlParameters) {
        return sendToController(url, urlParameters, "POST");
    }

    private String sendToController(String url, String urlParameters, String method) {
        try {
            byte[] postData = urlParameters.getBytes(StandardCharsets.UTF_8);

            URL cookieUrl = new URL(url);
            HttpsURLConnection connection = (HttpsURLConnection) cookieUrl.openConnection();

            connection.setInstanceFollowRedirects(true);
            connection.setRequestMethod(method);
            //for(String cookie : cookies) {
            connection.setRequestProperty("Cookie", cookies.get(0) + "; " + cookies.get(1));
            //}

            if (urlParameters.length() > 0) {
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Length", Integer.toString(postData.length));
                connection.setUseCaches(false);

                try (DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
                    wr.write(postData);
                }
            }

            InputStream response = connection.getInputStream();
            String line = readResponse(response);
            if (!checkResponse(line)) {
                logger.error("Unifi response: " + line);

            }
            return line;
        } catch (MalformedURLException e) {
            logger.error("The URL '" + url + "' is malformed: " + e.toString());
        } catch (Exception e) {
            logger.error("Cannot send data " + urlParameters + " to url " + url + ". Exception: " + e.toString());
        }
        return "";
    }

    private UnifiGenericBindingProvider.UnifiBindingConfig getUnifiConfig(String itemName) {
        for (final UnifiBindingProvider provider : providers) {
            for (final String name : provider.getItemNames()) {
                if (itemName.equals(name)) {
                    return (UnifiGenericBindingProvider.UnifiBindingConfig) provider.getItemConfig(itemName);
                }
            }
        }
        return null;
    }

    /**
     * @{inheritDoc}
     */
    @Override
    protected void internalReceiveUpdate(String itemName, State newState) {
        // the code being executed when a state was sent on the openHAB
        // event bus goes here. This method is only called if one of the
        // BindingProviders provide a binding for the given 'itemName'.
        logger.debug("internalReceiveUpdate({},{}) is called!", itemName, newState);
    }

}
