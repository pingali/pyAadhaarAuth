from xml.dom.minidom import parse, parseString
import pprint
#import dumper

def authparse(s): 

  dom = parseString('<myxml>Some data<empty/> some more data</myxml>')
  pprint.pprint(dom, depth=4);
  #dumper.dumps(dom)

datasource = open('sample-auth.xml')
data = datasource.read()
#pprint.pprint(data)
authparse(data)
