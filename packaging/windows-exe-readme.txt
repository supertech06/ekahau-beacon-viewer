Ekahau Beacon Viewer - Windows
==============================

Decodes the raw 802.11 beacon information elements that Ekahau records in a
.esx survey but never shows you: transmit power, channel utilisation, country
and regulatory limits, 802.11k/v/r support, vendor elements, and the complete
element list for any access point.


Running it
----------
Double-click "Ekahau Beacon Viewer.exe". A console window opens and your
browser follows a second later.

To stop it, close the console window or use the Quit button in the page.

There is nothing to install. Python is bundled inside the executable.


SmartScreen
-----------
This executable is not code-signed, so Windows may warn about an unrecognised
app. Choose "More info" then "Run anyway".


Privacy
-------
Nothing is uploaded. The server binds to 127.0.0.1 only, reads the .esx from
your disk, and each launch uses a random URL token so nothing else on your
machine can reach it.


A note on transmit power
------------------------
The "Regulatory max" column shows the ceiling an AP advertises in its Country
element - commonly 36 dBm in the US. That is the legal limit every AP in the
country advertises, not what the radio is set to. Only the TPC Report column
is a real reading, and many enterprise vendors do not send one. If that column
is empty for your APs, get transmit power from the WLAN controller instead.
