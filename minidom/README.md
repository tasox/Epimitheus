#### Error Message

If you use wevtutl or any other tool to export the Windows Events in xml form and you find bad characters like 0xb5 the Minidom will fail. It will through you an error message like:

[!alt]()

The portion of the code that it has this problematic behavior is the file "Lib/xml/dom/expatbuilder.py" in line 910.

[!alt()]


