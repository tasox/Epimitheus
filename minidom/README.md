#### Minidom failed to decode hex chars like \xb5

If you use wevtutil or any other tool to export the Windows Events in xml form, may be these tools will fail to decode chars like "\xb5"=μ (e.g. μTorrent). As a result this oversight, minidom will also fail to parse yours xml file.

##### The portion of the code that it has this problematic behavior is the file "Lib/xml/dom/expatbuilder.py" in line 910.

![alt text](https://github.com/tasox/Epimitheus/blob/master/minidom/expatbuilderUnFixed.png)


#### Fixed
![alt text](https://github.com/tasox/Epimitheus/blob/master/minidom/expatbuilderFixed.png)



