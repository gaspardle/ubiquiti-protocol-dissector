# ubiquiti-protocol-dissector


ubiquiti-protocol-dissector is a wireshark dissector for the Ubiquiti discovery protocol used by the UniFi and EdgeMax devices.


## Installation 

Copy ubiquiti-discovery.lua to the Wireshark [plugin folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).

Windows:
Personal plugin folder ```%APPDATA%\Wireshark\plugins``` or the global plugin folder ```(Wireshark install dir)\plugins```


Linux:
```~/.local/lib/wireshark/plugins```