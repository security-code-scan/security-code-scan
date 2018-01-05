using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class WebConfigAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor RuleValidateRequest         = LocaleUtil.GetDescriptor("SCS0021");
        private static readonly DiagnosticDescriptor RuleEnableEventValidation   = LocaleUtil.GetDescriptor("SCS0022");
        private static readonly DiagnosticDescriptor RuleViewStateEncryptionMode = LocaleUtil.GetDescriptor("SCS0023");
        private static readonly DiagnosticDescriptor RuleEnableViewStateMac      = LocaleUtil.GetDescriptor("SCS0024");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(
            RuleValidateRequest, RuleEnableEventValidation, RuleViewStateEncryptionMode, RuleEnableViewStateMac);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterCompilationAction(Compilation);
        }

        private void Compilation(CompilationAnalysisContext ctx)
        {
            var additionalFiles = ctx.Options.AdditionalFiles;

            //Load Web.config files : ASP.net web application configuration
            var configFiles = additionalFiles.Where(file => Path.GetFileName(file.Path).StartsWith("Web.config"));

            foreach (AdditionalText file in configFiles.ToList())
            {
                string content = GetFileContent(file);
                AnalyzeConfigurationFile(content, file, ctx);
            }
        }

        private string GetFileContent(AdditionalText file)
        {
            var str = new StringBuilder();
            foreach (TextLine line in file.GetText().Lines)
            {
                str.Append(line);
            }

            return str.ToString();
        }

        private XAttribute AttributeInsensitive(XElement x, string attributeName)
        {
            //Taken from : http://stackoverflow.com/a/13526453/89769
            return x.Attributes()
                    .SingleOrDefault(xa =>
                                         string.Equals(xa.Name.LocalName,
                                                       attributeName,
                                                       StringComparison.CurrentCultureIgnoreCase));
        }

        public void AnalyzeConfigurationFile(string content, AdditionalText file, CompilationAnalysisContext context)
        {
            var doc = XDocument.Load(new StringReader(content));

            //ValidateRequest
            {
                IEnumerable<XElement> pagesNodes = doc.Descendants("pages")
                                                      .Where(c => AttributeInsensitive(c, "validateRequest")
                                                                      ?.Value != "true");

                foreach (var page in pagesNodes)
                {
                    if (AttributeInsensitive(page, "validateRequest")?.Value.ToLower() != "false")
                        continue;

                    var lineInfo   = (IXmlLineInfo)page;
                    int lineNumber = lineInfo.HasLineInfo() ? lineInfo.LineNumber : 1;

                    Location loc = AnalyzerUtil.CreateLocation(file.Path, lineNumber);
                    context.ReportDiagnostic(Diagnostic.Create(RuleValidateRequest, loc));
                }
            }

            //EnableEventValidation
            {
                IEnumerable<XElement> pagesNodes = doc.Descendants("pages")
                                                      .Where(c => AttributeInsensitive(c, "enableEventValidation")
                                                                      ?.Value != "true");

                foreach (var page in pagesNodes)
                {
                    if (AttributeInsensitive(page, "enableEventValidation")?.Value.ToLower() != "false")
                        continue;

                    var lineInfo   = (IXmlLineInfo)page;
                    int lineNumber = lineInfo.HasLineInfo() ? lineInfo.LineNumber : 1;

                    Location loc = AnalyzerUtil.CreateLocation(file.Path, lineNumber);
                    context.ReportDiagnostic(Diagnostic.Create(RuleEnableEventValidation, loc));
                }
            }

            //ViewStateEncryptionMode
            {
                IEnumerable<XElement> pagesNodes = doc.Descendants("pages")
                                                      .Where(c => AttributeInsensitive(c, "viewStateEncryptionMode")
                                                                      ?.Value != "true");

                foreach (var page in pagesNodes)
                {
                    if (AttributeInsensitive(page, "viewStateEncryptionMode")?.Value.ToLower() != "auto" &&
                        AttributeInsensitive(page, "viewStateEncryptionMode")?.Value.ToLower() != "never")
                    {
                        continue;
                    }

                    var lineInfo   = (IXmlLineInfo)page;
                    int lineNumber = lineInfo.HasLineInfo() ? lineInfo.LineNumber : 1;

                    Location loc = AnalyzerUtil.CreateLocation(file.Path, lineNumber);
                    context.ReportDiagnostic(Diagnostic.Create(RuleViewStateEncryptionMode, loc));
                }
            }

            //EnableViewStateMac: https://blogs.msdn.microsoft.com/webdev/2014/09/09/farewell-enableviewstatemac/
            {
                IEnumerable<XElement> pagesNodes = doc.Descendants("pages")
                                                      .Where(c => AttributeInsensitive(c, "enableViewStateMac")
                                                                      ?.Value != "true");

                foreach (var page in pagesNodes)
                {
                    if (AttributeInsensitive(page, "enableViewStateMac")?.Value.ToLower() != "false")
                        continue;

                    var lineInfo   = (IXmlLineInfo)page;
                    int lineNumber = lineInfo.HasLineInfo() ? lineInfo.LineNumber : 1;

                    Location loc = AnalyzerUtil.CreateLocation(file.Path, lineNumber);
                    context.ReportDiagnostic(Diagnostic.Create(RuleEnableViewStateMac, loc));
                }
            }
        }
    }
}
