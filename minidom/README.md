#### Minidom failed to decode hex chars like \xb5

If you use wevtutl or any other tool to export the Windows Events in xml form, may be these tools will fail to decode chars like "\xb5"=μ (e.g. μTorrent).  you find bad characters like 0xb5 the Minidom will fail. As a result this oversight, minidom will also will fail to parse your xml file.

##### The portion of the code that it has this problematic behavior is the file "Lib/xml/dom/expatbuilder.py" in line 910.

![alt text](https://github.com/tasox/Epimitheus/blob/master/minidom/expatbuilderUnFixed.png)


![alt text](https://github.com/tasox/Epimitheus/blob/master/minidom/expatbuilderFixed.png)



