# org.openhab.binding.unifi
# initialization example (openhab.cfg)

```
2016-12-19 20:53:16.614 [INFO ] [.b.unifi.internal.UnifiBinding] - Detected 1 unifi APs
2016-12-19 20:53:16.615 [INFO ] [.b.unifi.internal.UnifiBinding] - Unifi AP with id: 580002bf403176465b707736 MAC: 44:d9:e7:f9:51:b4 has 4 wifi networks:
	 SSID: ubiquity name: ath0 id: 546f8eb828f4c02484b23e86 radio: ng
	 SSID: guest name: ath1 id: 58582ccdccf248c860fcbdb4 radio: ng (GUEST)
	 SSID: ubiquity name: ath3 id: 546f8eb828f4c02484b23e86 radio: na
	 SSID: guest name: ath4 id: 58582ccdccf248c860fcbdb4 radio: na (GUEST)
2016-12-19 20:53:16.617 [INFO ] [.service.AbstractActiveService] - Unifi Refresh Service has been started
```


# items:

```
Switch Unifi_LED   "Unifi LED"    { unifi="led" }
Switch Unifi_blink_LED   "Unifi blink LED"   { unifi="blink#44:d9:e7:f9:51:b4" }
Switch GuestNetwork "Guest network" { unifi="enable_wlan#58582ccdccf248c860fcbdb4" }
Switch WifiNetwork "Wifi network" { unifi="enable_wlan#546f8eb828f4c02484b23e86" }
Switch RebootAP "Reboot AP"  { unifi="reboot#44:d9:e7:f9:51:b4" }
Switch DisableAP "Disable AP"  { unifi="disable_ap#580002bf403176465b707736" }
```
blinking control requires mac address of the unifi AP

# openhab.cfg:

```
######################## Unifi controller ###########################
unifi.username={username}
unifi.password={password}
unifi.controllerIP={controller ip}
unifi.controllerPort={controller port}
```