from jinja2 import Environment, FileSystemLoader
import os
import xml.etree.ElementTree as etree

THIS_DIR = os.path.dirname(os.path.abspath(__file__))

def render_template(filename,**args):
    print("Generating "+filename)
    j2_env = Environment(loader=FileSystemLoader(THIS_DIR+"/templates"),trim_blocks=True)
    main_html = j2_env.get_template(filename).render(args)
    header_html = j2_env.get_template("header.htm").render(args)
    footer_html = j2_env.get_template("footer.htm").render(args)
    with open(THIS_DIR+"/out_site/"+filename, "wb") as fh:
        fh.write(header_html)
        fh.write(main_html)
        fh.write(footer_html)

tree = etree.parse(THIS_DIR+'/../RoslynSecurityGuard/RoslynSecurityGuard/Messages.resx')
data_nodes = tree.findall('data')

print(len(data_nodes))

#Loading rule descriptions
rules = {}
for node in data_nodes:
    key_parts = node.attrib['name'].split("_")
    if(key_parts[1] == 'Title' or key_parts[1] == 'Message'):
        if(not rules.has_key(key_parts[0])):
            rules[key_parts[0]] = {}
        nodeValue = node.find('value').text
        if(key_parts[1] == 'Title'):
            nodeValue = nodeValue.replace('(Future)','(Future<a href="#configuration-files">*</a>)') #Link to the bottom of the page
        rules[key_parts[0]][key_parts[1]] = nodeValue.replace("{0}","X")

#print(rules)

download_link = "https://dotnet-security-guard.github.io/releases/RoslynSecurityGuard-1.0.0.vsix"

render_template('index.htm', title='Home' , latest_version='1.0.0', nb_rules=len(rules), download_link = download_link)
render_template('rules.htm', title='Rules', rules=rules)
