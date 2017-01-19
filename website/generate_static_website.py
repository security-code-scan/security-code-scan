from jinja2 import Environment, FileSystemLoader
import os
import yaml
from collections import OrderedDict
import os.path
import codecs

import sys
reload(sys)
sys.setdefaultencoding("utf-8")


THIS_DIR = os.path.dirname(os.path.abspath(__file__))

def render_template(templateFile,outFile,**args):
    print("Generating "+outFile)
    j2_env = Environment(loader=FileSystemLoader(THIS_DIR+"/templates"),trim_blocks=True)
    main_html = j2_env.get_template(templateFile).render(args)
    header_html = j2_env.get_template("header.htm").render(args)
    footer_html = j2_env.get_template("footer.htm").render(args)
    with open(THIS_DIR+"/out_site/"+outFile, "wb") as fh:
        fh.write(header_html)
        fh.write(main_html)
        fh.write(footer_html)

#Loading rule descriptions
#rules = OrderedDict()
rules = {}
with open("../RoslynSecurityGuard/RoslynSecurityGuard/Config/Messages.yml", 'r') as stream:
    try:
        data = yaml.load(stream)

        for msg_key in data:
            print "Loading "+msg_key
            
            descFile = "../RoslynSecurityGuard/RoslynSecurityGuard/Config/Descriptions/" + msg_key + ".html"
            if os.path.isfile(descFile):
                with codecs.open(descFile, 'r', encoding='utf-8') as descStream:
                    render_template('rule.htm',msg_key+".htm", title=data[msg_key]['title'], description=descStream.read())
            else:
                render_template('rule.htm',msg_key+".htm", title=data[msg_key]['title'], description=data[msg_key]['description']+"<br/><br/><i>A detailed description will soon be added.</i>")

            rules[msg_key] = {}
            rules[msg_key]['Title'] = data[msg_key]['title']
            rules[msg_key]['Message'] = data[msg_key]['description']
    except yaml.YAMLError as exc:
        print(exc)

nb_sinks = 0
with open("../RoslynSecurityGuard/RoslynSecurityGuard/Config/Sinks.yml", 'r') as stream:
    try:
        data = yaml.load(stream)
        nb_sinks = len(data)
        print "%s injection sinks" % (nb_sinks)
    except yaml.YAMLError as exc:
        print(exc)


nb_passwords = 0
with open("../RoslynSecurityGuard/RoslynSecurityGuard/Config/Passwords.yml", 'r') as stream:
    try:
        data = yaml.load(stream)
        nb_passwords = len(data)
        print "%s passwords sinks" % (nb_passwords)
    except yaml.YAMLError as exc:
        print(exc)

#Building the complete website

download_link = "https://marketplace.visualstudio.com/items?itemName=PhilippeArteau.RoslynSecurityGuard"
version = '2.1.0'

render_template('index.htm', 'index.htm', title='Home' , latest_version=version, nb_rules=len(rules), nb_signatures=(len(rules)+nb_sinks+nb_passwords), download_link = download_link)
render_template('rules.htm', 'rules.htm', title='Rules', rules=rules )
