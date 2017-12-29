import os
import os.path

def writeGroup(outFile, rulesDir, groupMdFile, group):
    groupFile = open(os.path.join(rulesDir, groupMdFile), "r")
    outFile.write(groupFile.read())
    outFile.write("\n")
    groupFile.close()
    for md in group:
        mdFile = open(os.path.join(rulesDir, md), "r")
        outFile.write(mdFile.read())
        outFile.write("\n")
        mdFile.close()

sqliGroup = ["0002.md", "0014.md", "0020.md", "0025.md", "0026.md"]
injectionGroup = ["0001.md", "0003.md", "0007.md", "0018.md", "0029.md"]
cryptoGroup = ["0004.md", "0005.md", "0006.md", "0010.md", "0011.md", "0012.md", "0013.md"]
cookiesGroup = ["0008.md", "0009.md"]
viewStateGroup = ["0023.md", "0024.md"]
requestValidationGroup = ["0017.md", "0021.md"]
passwordGroup = ["0015.md", "0034.md", "0032.md", "0033.md"]
miscGroup = ["0016.md", "0019.md", "0022.md"]

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
outFile = open(os.path.join(THIS_DIR, "out_site/readme.md"), "w")
outFile.write("# Rules\n")

rulesDir = os.path.join(THIS_DIR, "rules")
writeGroup(outFile, rulesDir, "sqli.md", sqliGroup)
writeGroup(outFile, rulesDir, "injection.md", injectionGroup)
writeGroup(outFile, rulesDir, "cryptography.md", cryptoGroup)
writeGroup(outFile, rulesDir, "cookies.md", cookiesGroup)
writeGroup(outFile, rulesDir, "viewstate.md", viewStateGroup)
writeGroup(outFile, rulesDir, "requestvalidation.md", requestValidationGroup)
writeGroup(outFile, rulesDir, "password.md", passwordGroup)
writeGroup(outFile, rulesDir, "misc.md", miscGroup)

outFile.close()
