using System;
using System.Collections.Generic;
using System.Linq;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.CodeAnalysis.Text;
using System.Xml.Linq;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class WebConfigAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor RuleValidateRequest = AnalyzerUtil.GetDescriptorFromResource("SG0021", "ValidateRequestFalse", DiagnosticSeverity.Warning);
        private static DiagnosticDescriptor RuleEnableEventValidation = AnalyzerUtil.GetDescriptorFromResource("SG0022", "EnableEventValidationFalse", DiagnosticSeverity.Warning);
        private static DiagnosticDescriptor RuleViewStateEncryptionMode = AnalyzerUtil.GetDescriptorFromResource("SG0023", "ViewStateEncryptionModeFalse", DiagnosticSeverity.Warning);
        private static DiagnosticDescriptor RuleEnableViewStateMac = AnalyzerUtil.GetDescriptorFromResource("SG0024", "EnableViewStateMacFalse", DiagnosticSeverity.Warning);


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
            StringBuilder str = new StringBuilder();
            foreach (TextLine line in file.GetText().Lines)
            {
                str.Append(line);
            }
            return str.ToString();
        }

        private XAttribute AttributeInsensitive(XElement x,string attributeName)
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

            XDocument doc = XDocument.Load(new StringReader(content));

            //ValidateRequest
            {
                IEnumerable<XElement> pagesNodes = from c in doc.Descendants("pages")
                    where AttributeInsensitive(c,"validateRequest")?.Value != "true"
                    select c;

                foreach (var page in pagesNodes)
                {
                    if (AttributeInsensitive(page,"validateRequest")?.Value.ToLower() == "false")
                    {
                        var lineInfo = (IXmlLineInfo) page;
                        int lineNumber = lineInfo.HasLineInfo() ? lineInfo.LineNumber : 1;

                        Location loc = AnalyzerUtil.CreateLocation(file.Path, lineNumber);
                        context.ReportDiagnostic(Diagnostic.Create(RuleValidateRequest, loc));
                    }
                }
            }
            //EnableEventValidation
            {
                IEnumerable<XElement> pagesNodes = from c in doc.Descendants("pages")
                                                   where AttributeInsensitive(c,"enableEventValidation")?.Value != "true"
                                                   select c;
                foreach (var page in pagesNodes)
                {
                    if (AttributeInsensitive(page,"enableEventValidation")?.Value.ToLower() == "false")
                    {
                        var lineInfo = (IXmlLineInfo) page;
                        int lineNumber = lineInfo.HasLineInfo() ? lineInfo.LineNumber : 1;

                        Location loc = AnalyzerUtil.CreateLocation(file.Path, lineNumber);
                        context.ReportDiagnostic(Diagnostic.Create(RuleEnableEventValidation, loc));
                    }
                }
            }
            //ViewStateEncryptionMode
            {
                IEnumerable<XElement> pagesNodes = from c in doc.Descendants("pages")
                                                   where AttributeInsensitive(c,"viewStateEncryptionMode")?.Value != "true"
                                                   select c;
                foreach (var page in pagesNodes)
                {
                    if (AttributeInsensitive(page,"viewStateEncryptionMode")?.Value.ToLower() == "auto" ||
                        AttributeInsensitive(page,"viewStateEncryptionMode")?.Value.ToLower() == "never") //Always, Auto & Never
                    {
                        var lineInfo = (IXmlLineInfo)page;
                        int lineNumber = lineInfo.HasLineInfo() ? lineInfo.LineNumber : 1;

                        Location loc = AnalyzerUtil.CreateLocation(file.Path, lineNumber);
                        context.ReportDiagnostic(Diagnostic.Create(RuleViewStateEncryptionMode, loc));
                    }
                }
            }
            //EnableViewStateMac: https://blogs.msdn.microsoft.com/webdev/2014/09/09/farewell-enableviewstatemac/
            {
                IEnumerable<XElement> pagesNodes = from c in doc.Descendants("pages")
                                                   where AttributeInsensitive(c, "enableViewStateMac")?.Value != "true"
                                                   select c;
                foreach (var page in pagesNodes)
                {
                    if (AttributeInsensitive(page, "enableViewStateMac")?.Value.ToLower() == "false")
                    {
                        var lineInfo = (IXmlLineInfo)page;
                        int lineNumber = lineInfo.HasLineInfo() ? lineInfo.LineNumber : 1;

                        Location loc = AnalyzerUtil.CreateLocation(file.Path, lineNumber);
                        context.ReportDiagnostic(Diagnostic.Create(RuleEnableViewStateMac, loc));
                    }
                }
            }
        }
    }
}
