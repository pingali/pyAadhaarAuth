
from xml.dom.minidom import Document
# Create the minidom document
doc = Document()
# Create the <wml> base element
wml = doc.createElement("wml")
doc.appendChild(wml)
# Create the main <card> element
maincard = doc.createElement("card")
maincard.setAttribute("id", "main")
wml.appendChild(maincard)
# Create a <p> element
paragraph1 = doc.createElement("p")
maincard.appendChild(paragraph1)
# Give the <p> elemenet some text
ptext = doc.createTextNode("This is a test!")
paragraph1.appendChild(ptext)
# Print our newly created XML
print doc.toprettyxml(indent="  ")

