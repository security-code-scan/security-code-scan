import os
import os.path

def appendFile(outFile, inFile):
    mdFile = open(inFile, "r")
    outFile.write(mdFile.read())
    outFile.write("\n")
    mdFile.close()

def writeGroup(outFile, rulesDir, groupMdFile, group):
    groupFile = open(os.path.join(rulesDir, groupMdFile), "r")
    outFile.write(groupFile.read())
    outFile.write("\n")
    groupFile.close()
    for md in group:
        outFile.write('<div id="SCS{}"></div>\n\n'.format(md))
        appendFile(outFile, os.path.join(rulesDir, md + ".md"))

injectionGroup = ["0001", "0002", "0003", "0007", "0018", "0029", "0026", "0031"]
cryptoGroup = ["0004", "0005", "0006", "0010", "0013"]
cookiesGroup = ["0008", "0009"]
viewStateGroup = ["0023", "0024"]
requestValidationGroup = ["0017", "0021", "0030"]
passwordGroup = ["0015", "0034", "0032", "0033"]
miscGroup = ["0011", "0012", "0016", "0019", "0022", "0027", "0028"]

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
outFile = open(os.path.join(THIS_DIR, "out_site/readme.md"), "w")
appendFile(outFile, os.path.join(THIS_DIR, "facts.md"))
appendFile(outFile, os.path.join(THIS_DIR, "installation.md"))
appendFile(outFile, os.path.join(THIS_DIR, "configuration.md"))

outFile.write("# Rules\n")
rulesDir = os.path.join(THIS_DIR, "rules")
writeGroup(outFile, rulesDir, "injection.md", injectionGroup)
writeGroup(outFile, rulesDir, "cryptography.md", cryptoGroup)
writeGroup(outFile, rulesDir, "cookies.md", cookiesGroup)
writeGroup(outFile, rulesDir, "viewstate.md", viewStateGroup)
writeGroup(outFile, rulesDir, "requestvalidation.md", requestValidationGroup)
writeGroup(outFile, rulesDir, "password.md", passwordGroup)
writeGroup(outFile, rulesDir, "misc.md", miscGroup)

appendFile(outFile, os.path.join(THIS_DIR, "releasenotes.md"))

outFile.close()
