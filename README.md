# org.openhab.binding.unifi

# items:

```
Switch Unifi_LED   "Unifi LED"   (FF_Corridor)   { unifi="led" }
Switch Unifi_blink_LED   "Unifi blink LED"   (FF_Corridor)   { unifi="blink#44:d9:e7:f9:51:b4" }
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